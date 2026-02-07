package bytesize

import (
	"fmt"
	"math"
	"testing"
)

func TestBytesize(t *testing.T) {
	t.Run("parse", func(t *testing.T) {
		tests := []struct {
			name        string
			input       string
			wantPercent float64
			wantBytes   int64
			wantOk      bool
		}{
			{name: "empty", input: "", wantPercent: 0, wantBytes: 0, wantOk: true},
			{name: "negative_percent", input: "-50%", wantOk: false},
			{name: "zero_percent", input: "0%", wantPercent: 0, wantOk: true},
			{name: "fifty_percent", input: "50%", wantPercent: 50, wantOk: true},
			{name: "percent_decimal_low", input: "50.1%", wantPercent: 50.1, wantOk: true},
			{name: "percent_decimal_high", input: "50.9%", wantPercent: 50.9, wantOk: true},
			{name: "percent_with_spaces", input: " 50 % ", wantPercent: 50, wantOk: true},
			{name: "hundred_percent", input: "100%", wantPercent: 100, wantOk: true},
			{name: "over_hundred_percent", input: "150%", wantOk: false},
			{name: "invalid_percent", input: "invalid%", wantOk: false},
			{name: "invalid_string", input: "invalid", wantOk: false},
			{name: "negative_number", input: "-1", wantOk: false},
			{name: "zero", input: "0", wantOk: true},
			{name: "decimal_low", input: ".1", wantOk: true},
			{name: "decimal_high", input: ".9", wantBytes: 1, wantOk: true},
			{name: "plain_number", input: "1000", wantBytes: 1000, wantOk: true},
			{name: "plain_decimal_low", input: "1000.1", wantBytes: 1000, wantOk: true},
			{name: "plain_decimal_high", input: "1000.9", wantBytes: 1001, wantOk: true},
			{name: "plain_1024", input: "1024", wantBytes: 1024, wantOk: true},
			{name: "negative_bytes", input: "-1B", wantOk: false},
			{name: "zero_bytes", input: "0B", wantOk: true},
			{name: "one_byte", input: "1B", wantBytes: 1, wantOk: true},
			{name: "suffix_only", input: "B", wantOk: false},
			{name: "bytes_with_spaces", input: " 1 B ", wantBytes: 1, wantOk: true},
			{name: "zero_kilo", input: "0K", wantOk: true},
			{name: "one_kilo", input: "1K", wantBytes: 1024, wantOk: true},
			{name: "one_kb", input: "1KB", wantBytes: 1024, wantOk: true},
			{name: "one_kib", input: "1KiB", wantBytes: 1024, wantOk: true},
			{name: "one_mega", input: "1M", wantBytes: 1024 * 1024, wantOk: true},
			{name: "two_point_five_mb", input: "2.5MB", wantBytes: int64(2.5 * 1024 * 1024), wantOk: true},
			{name: "one_giga", input: "1G", wantBytes: 1024 * 1024 * 1024, wantOk: true},
			{name: "one_gb", input: "1GB", wantBytes: 1024 * 1024 * 1024, wantOk: true},
			{name: "one_gib", input: "1GiB", wantBytes: 1024 * 1024 * 1024, wantOk: true},
			{name: "one_tera", input: "1T", wantBytes: 1024 * 1024 * 1024 * 1024, wantOk: true},
			{name: "one_tb", input: "1TB", wantBytes: 1024 * 1024 * 1024 * 1024, wantOk: true},
			{name: "one_tib", input: "1TiB", wantBytes: 1024 * 1024 * 1024 * 1024, wantOk: true},
			{name: "unknown_suffix", input: "1XB", wantOk: false},
			{name: "max_float", input: fmt.Sprintf("%f", math.MaxFloat64), wantOk: false},
			{name: "overflow", input: fmt.Sprintf("1%f", math.MaxFloat64), wantOk: false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				p, b, err := Parse(tt.input)
				if tt.wantOk && err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				} else if !tt.wantOk && err == nil {
					t.Error("expected error, got nil")
					return
				}
				if p != tt.wantPercent || b != tt.wantBytes {
					t.Errorf("got p=%f b=%d, want p=%f b=%d", p, b, tt.wantPercent, tt.wantBytes)
				}
			})
		}
	})

	t.Run("format", func(t *testing.T) {
		tests := []struct {
			name  string
			input int64
			want  string
		}{
			{name: "zero", input: 0, want: "0B"},
			{name: "one_byte", input: 1, want: "1B"},
			{name: "below_kilo", input: 1023, want: "1023B"},
			{name: "one_kilo", input: 1024, want: "1.0KB"},
			{name: "one_mega", input: 1024 * 1024, want: "1.0MB"},
			{name: "one_giga", input: 1024 * 1024 * 1024, want: "1.0GB"},
			{name: "max_int64", input: math.MaxInt64, want: "8388608.0TB"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if got := Format(tt.input); got != tt.want {
					t.Errorf("Format(%d) = %q, want %q", tt.input, got, tt.want)
				}
			})
		}
	})
}
