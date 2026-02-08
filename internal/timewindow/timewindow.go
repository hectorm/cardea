package timewindow

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata"
)

const maxValueLength = 4096

type TimeWindow struct {
	Windows []Window `json:"windows"`
}

func (tw *TimeWindow) Contains(t time.Time) bool {
	for i := range tw.Windows {
		if tw.Windows[i].Contains(t) {
			return true
		}
	}
	return false
}

type Range struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

type Window struct {
	DOW      []Range        `json:"dow"`
	Month    []Range        `json:"month"`
	Day      []Range        `json:"day"`
	Hour     []Range        `json:"hour"`
	Min      []Range        `json:"min"`
	Sec      []Range        `json:"sec"`
	Location *time.Location `json:"-"`
}

func (w *Window) Contains(t time.Time) bool {
	t = t.In(w.Location)

	if !matchRanges(w.DOW, int(t.Weekday())) {
		return false
	}
	if !matchRanges(w.Month, int(t.Month())) {
		return false
	}
	if !matchRanges(w.Day, t.Day()) {
		return false
	}
	if !matchRanges(w.Hour, t.Hour()) {
		return false
	}
	if !matchRanges(w.Min, t.Minute()) {
		return false
	}
	if !matchRanges(w.Sec, t.Second()) {
		return false
	}

	return true
}

func (w Window) MarshalJSON() ([]byte, error) {
	type windowAlias Window
	loc := "Local"
	if w.Location != nil {
		loc = w.Location.String()
	}
	return json.Marshal(struct {
		windowAlias
		Location string `json:"location"`
	}{
		windowAlias: windowAlias(w),
		Location:    loc,
	})
}

func (w *Window) UnmarshalJSON(data []byte) error {
	type windowAlias Window
	var raw struct {
		windowAlias
		Location string `json:"location"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	loc, err := time.LoadLocation(raw.Location)
	if err != nil {
		return fmt.Errorf("invalid timezone %q: %w", raw.Location, err)
	}
	*w = Window(raw.windowAlias)
	w.Location = loc
	return nil
}

type constraintDef struct {
	min   int
	max   int
	names map[string]int
}

var dowNames = map[string]int{
	"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6,
}

var monthNames = map[string]int{
	"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
	"jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

var constraintDefs = map[string]constraintDef{
	"dow":   {min: 0, max: 6, names: dowNames},
	"month": {min: 1, max: 12, names: monthNames},
	"day":   {min: 1, max: 31},
	"hour":  {min: 0, max: 23},
	"min":   {min: 0, max: 59},
	"sec":   {min: 0, max: 59},
}

func Parse(s string) (*TimeWindow, error) {
	if len(s) > maxValueLength {
		return nil, fmt.Errorf("value too long (%d characters, max %d)", len(s), maxValueLength)
	}

	if strings.TrimSpace(s) == "" {
		return nil, fmt.Errorf("empty value")
	}

	windowStrs := strings.Split(s, ",")
	windows := make([]Window, 0, len(windowStrs))

	for _, ws := range windowStrs {
		ws = strings.TrimSpace(ws)
		if ws == "" {
			return nil, fmt.Errorf("empty window in list")
		}

		w, err := parseWindow(ws)
		if err != nil {
			return nil, err
		}
		windows = append(windows, w)
	}

	return &TimeWindow{Windows: windows}, nil
}

func parseWindow(s string) (Window, error) {
	w := Window{Location: time.Local}
	seen := make(map[string]bool)

	fields := strings.FieldsSeq(s)
	for field := range fields {
		typ, val, ok := strings.Cut(field, ":")
		if !ok {
			return Window{}, fmt.Errorf("missing colon in constraint %q", field)
		}

		typLower := strings.ToLower(typ)

		if val == "" {
			return Window{}, fmt.Errorf("missing value for constraint %q", typLower)
		}

		if typLower == "tz" {
			if seen["tz"] {
				return Window{}, fmt.Errorf("duplicate constraint %q", typLower)
			}
			seen["tz"] = true
			loc, err := time.LoadLocation(val)
			if err != nil {
				return Window{}, fmt.Errorf("invalid timezone %q: %w", val, err)
			}
			w.Location = loc
			continue
		}

		def, ok := constraintDefs[typLower]
		if !ok {
			return Window{}, fmt.Errorf("unknown constraint type %q", typLower)
		}

		if seen[typLower] {
			return Window{}, fmt.Errorf("duplicate constraint %q", typLower)
		}
		seen[typLower] = true

		ranges, err := parseRanges(val, def)
		if err != nil {
			return Window{}, fmt.Errorf("invalid %s value %q: %w", typLower, val, err)
		}

		switch typLower {
		case "dow":
			w.DOW = ranges
		case "month":
			w.Month = ranges
		case "day":
			w.Day = ranges
		case "hour":
			w.Hour = ranges
		case "min":
			w.Min = ranges
		case "sec":
			w.Sec = ranges
		}
	}

	return w, nil
}

func parseRanges(s string, def constraintDef) ([]Range, error) {
	parts := strings.Split(s, "/")
	ranges := make([]Range, 0, len(parts))

	for _, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("empty range")
		}

		r, err := parseRange(part, def)
		if err != nil {
			return nil, err
		}
		ranges = append(ranges, r)
	}

	return ranges, nil
}

func parseRange(s string, def constraintDef) (Range, error) {
	// Try to split on the first hyphen. Both sides must parse as valid values
	// for the input to be treated as a range (e.g., "mon-fri", "8-17").
	// If either side fails, fall through to single-value parsing.
	if idx := strings.Index(s, "-"); idx > 0 {
		left := s[:idx]
		right := s[idx+1:]

		if right != "" {
			startVal, startErr := parseValue(left, def)
			endVal, endErr := parseValue(right, def)

			if startErr == nil && endErr == nil {
				if startVal > endVal {
					return Range{}, fmt.Errorf("invalid range %q: start (%d) > end (%d)", s, startVal, endVal)
				}
				return Range{Start: startVal, End: endVal}, nil
			}
		}
	}

	// Try as single value
	val, err := parseValue(s, def)
	if err != nil {
		return Range{}, err
	}
	return Range{Start: val, End: val}, nil
}

func parseValue(s string, def constraintDef) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("empty value")
	}

	// Try name lookup first
	if def.names != nil {
		if v, ok := def.names[strings.ToLower(s)]; ok {
			return v, nil
		}
	}

	// Reject negative numbers (leading minus sign)
	if s[0] == '-' {
		return 0, fmt.Errorf("negative value %q", s)
	}

	// Reject non-digit characters (prevents "9.5", "abc" etc.)
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid value %q", s)
		}
	}

	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid value %q: %w", s, err)
	}

	if v < int64(def.min) || v > int64(def.max) {
		return 0, fmt.Errorf("value %d out of range [%d, %d]", v, def.min, def.max)
	}

	return int(v), nil
}

func matchRanges(ranges []Range, val int) bool {
	if ranges == nil {
		return true
	}
	for _, r := range ranges {
		if val >= r.Start && val <= r.End {
			return true
		}
	}
	return false
}
