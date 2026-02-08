package timewindow

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		tests := []struct {
			name   string
			input  string
			numWin int
		}{
			{name: "single_value", input: "dow:mon", numWin: 1},
			{name: "named_range", input: "dow:mon-fri", numWin: 1},
			{name: "numeric_range", input: "hour:8-17", numWin: 1},
			{name: "multiple_ranges", input: "dow:mon-wed/fri", numWin: 1},
			{name: "split_ranges", input: "hour:8-13/15-17", numWin: 1},
			{name: "same_value_range", input: "hour:9-9", numWin: 1},
			{name: "case_insensitive", input: "dow:MoN-fRi", numWin: 1},
			{name: "boundary_values", input: "hour:0-23", numWin: 1},
			{name: "day_31", input: "day:31", numWin: 1},
			{name: "all_constraints", input: "dow:mon month:1 day:1 hour:0 min:0 sec:0", numWin: 1},
			{name: "combined_with_tz", input: "dow:mon-fri hour:8-17 tz:Europe/Madrid", numWin: 1},
			{name: "tz_only", input: "tz:UTC", numWin: 1},
			{name: "two_windows", input: "dow:mon-thu hour:8-17,dow:fri hour:8-14", numWin: 2},
			{name: "three_windows", input: "dow:mon,dow:wed,dow:fri", numWin: 3},
			{name: "per_window_tz", input: "hour:8-17 tz:Europe/Madrid,hour:8-17 tz:America/New_York", numWin: 2},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				tw, err := Parse(tt.input)
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if len(tw.Windows) != tt.numWin {
					t.Errorf("expected %d windows, got %d", tt.numWin, len(tw.Windows))
				}
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name  string
			input string
			errSS string
		}{
			{name: "empty", input: "", errSS: "empty"},
			{name: "whitespace_only", input: "   ", errSS: "empty"},
			{name: "unknown_type", input: "foo:bar", errSS: "unknown constraint type"},
			{name: "missing_value", input: "hour:", errSS: "missing value"},
			{name: "missing_colon", input: "dow", errSS: "missing colon"},
			{name: "missing_colon_no_sep", input: "hour8-17", errSS: "missing colon"},
			{name: "out_of_range_hour", input: "hour:25", errSS: "out of range"},
			{name: "out_of_range_dow", input: "dow:7", errSS: "out of range"},
			{name: "out_of_range_month", input: "month:0", errSS: "out of range"},
			{name: "out_of_range_month_13", input: "month:13", errSS: "out of range"},
			{name: "out_of_range_day_0", input: "day:0", errSS: "out of range"},
			{name: "out_of_range_day_32", input: "day:32", errSS: "out of range"},
			{name: "out_of_range_min_60", input: "min:60", errSS: "out of range"},
			{name: "out_of_range_sec_60", input: "sec:60", errSS: "out of range"},
			{name: "wrap_around_dow", input: "dow:fri-mon", errSS: "start"},
			{name: "wrap_around_hour", input: "hour:22-6", errSS: "start"},
			{name: "invalid_timezone", input: "tz:Invalid/Zone", errSS: "invalid timezone"},
			{name: "duplicate_constraint", input: "hour:9 hour:10", errSS: "duplicate"},
			{name: "duplicate_tz", input: "tz:UTC tz:UTC", errSS: "duplicate"},
			{name: "leading_comma", input: ",dow:mon", errSS: "empty window"},
			{name: "trailing_comma", input: "dow:mon,", errSS: "empty window"},
			{name: "double_comma", input: "dow:mon,,dow:tue", errSS: "empty window"},
			{name: "negative_number", input: "hour:-1", errSS: "negative"},
			{name: "non_integer", input: "hour:9.5", errSS: "invalid"},
			{name: "integer_overflow", input: "hour:999999999999", errSS: "out of range"},
			{name: "tz_invalid_colon", input: "tz:America/New:York", errSS: "invalid timezone"},
			{name: "value_too_long", input: "dow:" + strings.Repeat("mon/", 1025), errSS: "too long"},
			{name: "empty_range_slash", input: "hour:9/", errSS: "empty"},
			{name: "leading_slash", input: "hour:/9", errSS: "empty"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := Parse(tt.input)
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.errSS) {
					t.Errorf("expected error containing %q, got %q", tt.errSS, err.Error())
				}
			})
		}
	})
}

func TestContains(t *testing.T) {
	baseTime := time.Date(2006, 1, 2, 15, 4, 5, 0, time.UTC)

	t.Run("basic_matching", func(t *testing.T) {
		tests := []struct {
			name  string
			input string
			t     time.Time
			match bool
		}{
			{name: "dow_match", input: "dow:mon tz:UTC", t: baseTime, match: true},
			{name: "dow_no_match", input: "dow:tue tz:UTC", t: baseTime, match: false},
			{name: "dow_range_match", input: "dow:mon-fri tz:UTC", t: baseTime, match: true},
			{name: "dow_range_no_match", input: "dow:sat/sun tz:UTC", t: baseTime, match: false},
			{name: "hour_match", input: "hour:15 tz:UTC", t: baseTime, match: true},
			{name: "hour_no_match", input: "hour:16 tz:UTC", t: baseTime, match: false},
			{name: "hour_range_match", input: "hour:8-17 tz:UTC", t: baseTime, match: true},
			{name: "hour_range_no_match", input: "hour:16-17 tz:UTC", t: baseTime, match: false},
			{name: "month_match", input: "month:jan tz:UTC", t: baseTime, match: true},
			{name: "month_no_match", input: "month:feb tz:UTC", t: baseTime, match: false},
			{name: "day_match", input: "day:2 tz:UTC", t: baseTime, match: true},
			{name: "day_no_match", input: "day:3 tz:UTC", t: baseTime, match: false},
			{name: "min_match", input: "min:4 tz:UTC", t: baseTime, match: true},
			{name: "min_no_match", input: "min:5 tz:UTC", t: baseTime, match: false},
			{name: "sec_match", input: "sec:5 tz:UTC", t: baseTime, match: true},
			{name: "sec_no_match", input: "sec:6 tz:UTC", t: baseTime, match: false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				tw, err := Parse(tt.input)
				if err != nil {
					t.Fatalf("parse error: %v", err)
				}
				if got := tw.Contains(tt.t); got != tt.match {
					t.Errorf("Contains(%v) = %v, want %v", tt.t, got, tt.match)
				}
			})
		}
	})

	t.Run("and_logic", func(t *testing.T) {
		tests := []struct {
			name  string
			input string
			t     time.Time
			match bool
		}{
			{name: "both_match", input: "dow:mon hour:15 tz:UTC", t: baseTime, match: true},
			{name: "dow_fails", input: "dow:tue hour:15 tz:UTC", t: baseTime, match: false},
			{name: "hour_fails", input: "dow:mon hour:16 tz:UTC", t: baseTime, match: false},
			{name: "both_fail", input: "dow:tue hour:16 tz:UTC", t: baseTime, match: false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				tw, err := Parse(tt.input)
				if err != nil {
					t.Fatalf("parse error: %v", err)
				}
				if got := tw.Contains(tt.t); got != tt.match {
					t.Errorf("Contains(%v) = %v, want %v", tt.t, got, tt.match)
				}
			})
		}
	})

	t.Run("or_logic", func(t *testing.T) {
		tests := []struct {
			name  string
			input string
			t     time.Time
			match bool
		}{
			{name: "first_matches", input: "dow:mon tz:UTC,dow:tue tz:UTC", t: baseTime, match: true},
			{name: "second_matches", input: "dow:tue tz:UTC,dow:mon tz:UTC", t: baseTime, match: true},
			{name: "neither_matches", input: "dow:tue tz:UTC,dow:wed tz:UTC", t: baseTime, match: false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				tw, err := Parse(tt.input)
				if err != nil {
					t.Fatalf("parse error: %v", err)
				}
				if got := tw.Contains(tt.t); got != tt.match {
					t.Errorf("Contains(%v) = %v, want %v", tt.t, got, tt.match)
				}
			})
		}
	})

	t.Run("multiple_ranges_slash", func(t *testing.T) {
		tw, err := Parse("hour:8-13/15-17 tz:UTC")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}

		at10 := time.Date(2006, 1, 2, 10, 0, 0, 0, time.UTC)
		if !tw.Contains(at10) {
			t.Error("expected hour:8-13/15-17 to match 10:00")
		}

		at14 := time.Date(2006, 1, 2, 14, 0, 0, 0, time.UTC)
		if tw.Contains(at14) {
			t.Error("expected hour:8-13/15-17 not to match 14:00")
		}

		at16 := time.Date(2006, 1, 2, 16, 0, 0, 0, time.UTC)
		if !tw.Contains(at16) {
			t.Error("expected hour:8-13/15-17 to match 16:00")
		}
	})

	t.Run("timezone", func(t *testing.T) {
		madrid, err := time.LoadLocation("Europe/Madrid")
		if err != nil {
			t.Fatalf("failed to load timezone: %v", err)
		}

		tw, err := Parse("hour:8-17 tz:Europe/Madrid")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}

		// 10:00 Madrid time
		madridTime := time.Date(2006, 1, 2, 10, 0, 0, 0, madrid)
		if !tw.Contains(madridTime) {
			t.Error("expected to match 10:00 Madrid time")
		}

		// 7:00 UTC = 8:00 CET (Madrid winter time, UTC+1), should match
		utcTime := time.Date(2006, 1, 2, 7, 0, 0, 0, time.UTC)
		if !tw.Contains(utcTime) {
			t.Error("expected to match 7:00 UTC (= 8:00 Madrid)")
		}

		// 6:59 UTC = 7:59 CET, should not match
		utcBefore := time.Date(2006, 1, 2, 6, 59, 0, 0, time.UTC)
		if tw.Contains(utcBefore) {
			t.Error("expected not to match 6:59 UTC (= 7:59 Madrid)")
		}
	})

	t.Run("per_window_timezone", func(t *testing.T) {
		// Window 1: 8-17 Madrid, Window 2: 8-17 New York
		tw, err := Parse("hour:8-17 tz:Europe/Madrid,hour:8-17 tz:America/New_York")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}

		// 15:00 UTC: Madrid = 16:00 CET (in range), New York = 10:00 EST (in range)
		utc15 := time.Date(2006, 1, 2, 15, 0, 0, 0, time.UTC)
		if !tw.Contains(utc15) {
			t.Error("expected 15:00 UTC to match (both windows)")
		}

		// 20:00 UTC: Madrid = 21:00 CET (out), New York = 15:00 EST (in range)
		utc20 := time.Date(2006, 1, 2, 20, 0, 0, 0, time.UTC)
		if !tw.Contains(utc20) {
			t.Error("expected 20:00 UTC to match (New York window)")
		}

		// 23:00 UTC: Madrid = 00:00 CET next day (out), New York = 18:00 EST (out)
		utc23 := time.Date(2006, 1, 2, 23, 0, 0, 0, time.UTC)
		if tw.Contains(utc23) {
			t.Error("expected 23:00 UTC not to match (neither window)")
		}
	})
}

func TestJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "all_constraints", input: "dow:mon-fri month:jan day:2 hour:8-17 min:0-30 sec:0 tz:UTC"},
		{name: "multiple_windows", input: "dow:mon-thu hour:8-17 tz:Europe/Madrid,dow:fri hour:8-14 tz:America/New_York"},
		{name: "split_ranges", input: "hour:8-13/15-17 tz:UTC"},
		{name: "local_default", input: "hour:8-17"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original, err := Parse(tt.input)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}

			data, err := json.Marshal(original)
			if err != nil {
				t.Fatalf("marshal error: %v", err)
			}

			var restored TimeWindow
			if err := json.Unmarshal(data, &restored); err != nil {
				t.Fatalf("unmarshal error: %v", err)
			}

			restoredData, err := json.Marshal(restored)
			if err != nil {
				t.Fatalf("re-marshal error: %v", err)
			}

			if string(data) != string(restoredData) {
				t.Errorf("round-trip mismatch:\n  original: %s\n  restored: %s", data, restoredData)
			}
		})
	}

	t.Run("unmarshal_invalid_timezone", func(t *testing.T) {
		raw := `{"windows":[{"dow":null,"month":null,"day":null,"hour":null,"min":null,"sec":null,"location":"Invalid/Zone"}]}`
		var tw TimeWindow
		if err := json.Unmarshal([]byte(raw), &tw); err == nil {
			t.Error("expected error for invalid timezone, got nil")
		}
	})
}
