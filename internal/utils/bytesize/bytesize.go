package bytesize

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

var units = map[string]float64{
	"":    1,
	"B":   1,
	"K":   1024,
	"KB":  1024,
	"KIB": 1024,
	"M":   1024 * 1024,
	"MB":  1024 * 1024,
	"MIB": 1024 * 1024,
	"G":   1024 * 1024 * 1024,
	"GB":  1024 * 1024 * 1024,
	"GIB": 1024 * 1024 * 1024,
	"T":   1024 * 1024 * 1024 * 1024,
	"TB":  1024 * 1024 * 1024 * 1024,
	"TIB": 1024 * 1024 * 1024 * 1024,
}

func Parse(val string) (percent float64, bytes int64, err error) {
	val = strings.TrimSpace(strings.ToUpper(val))
	if val == "" || val == "0" || val == "0%" || val == "0B" {
		return 0, 0, nil
	}

	if strings.HasSuffix(val, "%") {
		p, err := parsePercent(val)
		if err != nil {
			return 0, 0, err
		}
		return p, 0, nil
	}

	b, err := parseBytes(val)
	if err != nil {
		return 0, 0, err
	}
	return 0, b, nil
}

func parsePercent(s string) (float64, error) {
	num := strings.TrimSuffix(s, "%")
	p, err := strconv.ParseFloat(strings.TrimSpace(num), 64)
	if err != nil {
		return 0, err
	}
	if p < 0 || p > 100 {
		return 0, fmt.Errorf("percentage out of range: %v", p)
	}
	return p, nil
}

func parseBytes(s string) (int64, error) {
	i := 0
	for ; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && c != '.' {
			break
		}
	}
	num, unit := strings.TrimSpace(s[:i]), strings.TrimSpace(s[i:])
	if num == "" {
		return 0, fmt.Errorf("missing number in size: %q", s)
	}

	f, err := strconv.ParseFloat(num, 64)
	if err != nil {
		return 0, err
	}

	mult, ok := units[unit]
	if !ok {
		return 0, fmt.Errorf("invalid size unit: %q", unit)
	}

	bytes := f * mult
	if bytes < 0 || bytes > math.MaxInt64 {
		return 0, fmt.Errorf("size out of range")
	}
	return int64(math.Round(bytes)), nil
}

func Format(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%dB", n)
	}

	types := []string{"KB", "MB", "GB", "TB"}
	val := float64(n)
	unit := "B"
	for _, t := range types {
		if val < 1024 {
			break
		}
		val = val / 1024
		unit = t
	}
	return fmt.Sprintf("%.1f%s", val, unit)
}
