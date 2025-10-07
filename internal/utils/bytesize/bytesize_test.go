package bytesize

import (
	"fmt"
	"math"
	"testing"
)

func TestBytesize(t *testing.T) {
	t.Run("parse", func(t *testing.T) {
		cases := map[string]struct {
			percent float64
			bytes   int64
			ok      bool
		}{
			"":                                  {0, 0, true},
			"-50%":                              {0, 0, false},
			"0%":                                {0, 0, true},
			"50%":                               {50, 0, true},
			"50.1%":                             {50.1, 0, true},
			"50.9%":                             {50.9, 0, true},
			" 50 % ":                            {50, 0, true},
			"100%":                              {100, 0, true},
			"150%":                              {0, 0, false},
			"invalid%":                          {0, 0, false},
			"invalid":                           {0, 0, false},
			"-1":                                {0, 0, false},
			"0":                                 {0, 0, true},
			".1":                                {0, 0, true},
			".9":                                {0, 1, true},
			"1000":                              {0, 1000, true},
			"1000.1":                            {0, 1000, true},
			"1000.9":                            {0, 1001, true},
			"1024":                              {0, 1024, true},
			"-1B":                               {0, 0, false},
			"0B":                                {0, 0, true},
			"1B":                                {0, 1, true},
			"B":                                 {0, 0, false},
			" 1 B ":                             {0, 1, true},
			"0K":                                {0, 0, true},
			"1K":                                {0, 1024, true},
			"1KB":                               {0, 1024, true},
			"1KiB":                              {0, 1024, true},
			"1M":                                {0, 1024 * 1024, true},
			"2.5MB":                             {0, int64(2.5 * 1024 * 1024), true},
			"1G":                                {0, 1024 * 1024 * 1024, true},
			"1GB":                               {0, 1024 * 1024 * 1024, true},
			"1GiB":                              {0, 1024 * 1024 * 1024, true},
			"1T":                                {0, 1024 * 1024 * 1024 * 1024, true},
			"1TB":                               {0, 1024 * 1024 * 1024 * 1024, true},
			"1TiB":                              {0, 1024 * 1024 * 1024 * 1024, true},
			"1XB":                               {0, 0, false},
			fmt.Sprintf("%f", math.MaxFloat64):  {0, 0, false},
			fmt.Sprintf("1%f", math.MaxFloat64): {0, 0, false},
		}

		for s, want := range cases {
			p, b, err := Parse(s)
			if want.ok && err != nil {
				t.Errorf("%s: unexpected err: %v", s, err)
				return
			} else if !want.ok && err == nil {
				t.Errorf("%s: expected error but got none", s)
				return
			}
			if p != want.percent || b != want.bytes {
				t.Errorf("%s: got p=%f b=%d want p=%f b=%d", s, p, b, want.percent, want.bytes)
				return
			}
		}
	})

	t.Run("format", func(t *testing.T) {
		cases := map[int64]string{
			0:                  "0B",
			1:                  "1B",
			1023:               "1023B",
			1024:               "1.0KB",
			1024 * 1024:        "1.0MB",
			1024 * 1024 * 1024: "1.0GB",
			math.MaxInt64:      "8388608.0TB",
		}

		for n, want := range cases {
			got := Format(n)
			if got != want {
				t.Errorf("%d: got %s want %s", n, got, want)
				return
			}
		}
	})
}
