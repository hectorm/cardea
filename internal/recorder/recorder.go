package recorder

import (
	"compress/flate"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/hectorm/cardea/internal/utils/disk"
)

type AsciicastV3Recorder struct {
	path    string
	file    *os.File
	writer  *gzip.Writer
	pending int
	timer   *time.Timer
	prev    time.Time
	mu      sync.Mutex
}

type AsciicastV3Header struct {
	Version   uint8             `json:"version"`
	Term      AsciicastV3Term   `json:"term"`
	Timestamp int64             `json:"timestamp"`
	Command   string            `json:"command,omitempty"`
	Title     string            `json:"title,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
}

type AsciicastV3Term struct {
	Cols uint32 `json:"cols"`
	Rows uint32 `json:"rows"`
	Type string `json:"type,omitempty"`
}

type AsciicastV3Event [3]any

func NewAsciicastV3Header(title string) *AsciicastV3Header {
	return &AsciicastV3Header{
		Version:   3,
		Term:      AsciicastV3Term{Cols: 80, Rows: 24},
		Timestamp: time.Now().Unix(),
		Title:     title,
		Env:       map[string]string{},
	}
}

func NewAsciicastV3Recorder(path string) *AsciicastV3Recorder {
	return &AsciicastV3Recorder{
		path: filepath.Clean(path),
	}
}

func (r *AsciicastV3Recorder) WriteHeader(header *AsciicastV3Header) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.writer != nil {
		return nil
	}

	file, err := os.OpenFile(filepath.Join(r.path), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	if err := disk.LockFile(file); err != nil {
		slog.Warn("failed to get exclusive lock on file", "file", r.path, "error", err)
	}

	r.file = file
	r.writer, _ = gzip.NewWriterLevel(file, flate.BestSpeed)
	r.prev = time.Now()

	headerBytes, err := json.Marshal(header)
	if err != nil {
		return err
	}

	headerLine := append(headerBytes, '\n')
	if _, err := r.writer.Write(headerLine); err != nil {
		return err
	}

	r.pending += len(headerLine)
	r.scheduleFlush()

	return nil
}

func (r *AsciicastV3Recorder) WriteExit(exitStatus uint32) error {
	defer func() { _ = r.Close() }() // Next writes will be ignored

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.writer == nil {
		return nil
	}

	now := time.Now()
	event := AsciicastV3Event{now.Sub(r.prev).Seconds(), "x", strconv.FormatUint(uint64(exitStatus), 10)}
	r.prev = now

	eventBytes, err := json.Marshal(event)
	if err != nil {
		return err
	}

	eventLine := append(eventBytes, '\n')
	if _, err := r.writer.Write(eventLine); err != nil {
		return err
	}

	r.pending += len(eventLine)
	r.scheduleFlush()

	return nil
}

func (r *AsciicastV3Recorder) WriteResize(cols, rows uint32) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.writer == nil {
		return nil
	}

	now := time.Now()
	event := AsciicastV3Event{now.Sub(r.prev).Seconds(), "r", fmt.Sprintf("%dx%d", cols, rows)}
	r.prev = now

	eventBytes, err := json.Marshal(event)
	if err != nil {
		return err
	}

	eventLine := append(eventBytes, '\n')
	if _, err := r.writer.Write(eventLine); err != nil {
		return err
	}

	r.pending += len(eventLine)
	r.scheduleFlush()

	return nil
}

func (r *AsciicastV3Recorder) Write(p []byte) (n int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.writer == nil {
		return len(p), nil
	}

	now := time.Now()
	event := AsciicastV3Event{now.Sub(r.prev).Seconds(), "o", string(p)}
	r.prev = now

	eventBytes, err := json.Marshal(event)
	if err != nil {
		return 0, err
	}

	eventLine := append(eventBytes, '\n')
	if _, err := r.writer.Write(eventLine); err != nil {
		return 0, err
	}

	r.pending += len(eventLine)
	r.scheduleFlush()

	return len(p), nil
}

func (r *AsciicastV3Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.timer != nil {
		r.timer.Stop()
		r.timer = nil
	}

	var wErr error
	if r.writer != nil {
		wErr = r.writer.Close()
		r.writer = nil
	}

	var fErr error
	if r.file != nil {
		_ = disk.UnlockFile(r.file)
		fErr = r.file.Close()
		r.file = nil
	}

	return errors.Join(wErr, fErr)
}

func (r *AsciicastV3Recorder) scheduleFlush() {
	const delay = 50 * time.Millisecond
	const threshold = 1024 // bytes

	if r.timer != nil {
		r.timer.Stop()
		r.timer = nil
	}

	if r.pending >= threshold {
		if r.writer != nil {
			_ = r.writer.Flush()
			r.pending = 0
		}
		return
	}

	r.timer = time.AfterFunc(delay, func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.writer != nil {
			_ = r.writer.Flush()
			r.pending = 0
		}
		r.timer = nil
	})
}
