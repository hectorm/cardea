package recorder

import (
	"compress/gzip"
	"encoding/json/v2"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAsciicastV3Recorder(t *testing.T) {
	readLines := func(t *testing.T, path string) []string {
		t.Helper()
		file, err := os.Open(filepath.Clean(path))
		if err != nil {
			t.Fatalf("failed to open recording: %v", err)
		}
		defer func() { _ = file.Close() }()
		reader, err := gzip.NewReader(file)
		if err != nil {
			t.Fatalf("failed to create gzip reader: %v", err)
		}
		content, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("failed to read recording: %v", err)
		}
		return strings.Split(strings.TrimSuffix(string(content), "\n"), "\n")
	}

	t.Run("header", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "session.cast.gz")
		rec := NewAsciicastV3Recorder(path)

		header := NewAsciicastV3Header("title")
		header.Env["TERM"] = "xterm"
		header.Env["LANG"] = "C"
		if err := rec.WriteHeader(header); err != nil {
			t.Errorf("failed to write header: %v", err)
			return
		}
		if err := rec.Close(); err != nil {
			t.Errorf("failed to close recorder: %v", err)
			return
		}

		lines := readLines(t, path)
		if len(lines) != 1 {
			t.Errorf("expected 1 line, got %d: %q", len(lines), lines)
			return
		}

		var decoded AsciicastV3Header
		if err := json.Unmarshal([]byte(lines[0]), &decoded); err != nil {
			t.Errorf("expected valid header, got %q: %v", lines[0], err)
			return
		}
		if decoded.Version != 3 || decoded.Title != "title" || decoded.Env["TERM"] != "xterm" {
			t.Errorf("expected header fields to round-trip, got %+v", decoded)
			return
		}
		if !strings.Contains(lines[0], `"env":{"LANG":"C","TERM":"xterm"}`) {
			t.Errorf("expected sorted env keys, got %s", lines[0])
			return
		}
	})

	t.Run("output", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "session.cast.gz")
		rec := NewAsciicastV3Recorder(path)

		if err := rec.WriteHeader(NewAsciicastV3Header("title")); err != nil {
			t.Errorf("failed to write header: %v", err)
			return
		}
		if _, err := rec.Write([]byte("café \xff\xfe \x1b[0m\r\n")); err != nil {
			t.Errorf("failed to write output: %v", err)
			return
		}
		if err := rec.WriteExit(42); err != nil {
			t.Errorf("failed to write exit: %v", err)
			return
		}

		lines := readLines(t, path)
		if len(lines) != 3 {
			t.Errorf("expected 3 lines, got %d: %q", len(lines), lines)
			return
		}

		var output, exit AsciicastV3Event
		if err := json.Unmarshal([]byte(lines[1]), &output); err != nil {
			t.Errorf("expected valid output event, got %q: %v", lines[1], err)
			return
		}
		if err := json.Unmarshal([]byte(lines[2]), &exit); err != nil {
			t.Errorf("expected valid exit event, got %q: %v", lines[2], err)
			return
		}
		if want := "café \ufffd\ufffd \x1b[0m\r\n"; output[1] != "o" || output[2] != want {
			t.Errorf("expected output event (%q, %q), got (%q, %q)", "o", want, output[1], output[2])
			return
		}
		if exit[1] != "x" || exit[2] != "42" {
			t.Errorf("expected exit event (%q, %q), got (%q, %q)", "x", "42", exit[1], exit[2])
			return
		}
	})
}
