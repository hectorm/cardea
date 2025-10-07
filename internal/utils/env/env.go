package env

import (
	"os"
	"strconv"
	"time"
)

func StringEnv(def string, keys ...string) string {
	for _, key := range keys {
		if val, ok := os.LookupEnv(key); ok {
			return val
		}
	}
	return def
}

func StringSliceEnv(def []string, keys ...string) []string {
	for _, key := range keys {
		if val, ok := os.LookupEnv(key); ok {
			return []string{val}
		}
	}
	return def
}

func IntEnv(def int, keys ...string) int {
	for _, key := range keys {
		if val, ok := os.LookupEnv(key); ok {
			if n, err := strconv.Atoi(val); err == nil {
				return n
			}
		}
	}
	return def
}

func FloatEnv(def float64, keys ...string) float64 {
	for _, key := range keys {
		if val, ok := os.LookupEnv(key); ok {
			if f, err := strconv.ParseFloat(val, 64); err == nil {
				return f
			}
		}
	}
	return def
}

func BoolEnv(def bool, keys ...string) bool {
	for _, key := range keys {
		if val, ok := os.LookupEnv(key); ok {
			if b, err := strconv.ParseBool(val); err == nil {
				return b
			}
		}
	}
	return def
}

func DurationEnv(def time.Duration, keys ...string) time.Duration {
	for _, key := range keys {
		if val, ok := os.LookupEnv(key); ok {
			if d, err := time.ParseDuration(val); err == nil {
				return d
			}
		}
	}
	return def
}
