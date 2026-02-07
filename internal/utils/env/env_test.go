package env

import (
	"testing"
	"time"
)

func TestEnv(t *testing.T) {
	t.Run("string_env", func(t *testing.T) {
		tests := []struct {
			name       string
			envs       map[string]string
			keys       []string
			defaultVal string
			want       string
		}{
			{name: "default", envs: nil, keys: []string{"FOO"}, defaultVal: "BAR", want: "BAR"},
			{name: "first", envs: map[string]string{"FOO1": "VAL1", "FOO2": "VAL2", "FOO3": "VAL3"}, keys: []string{"FOO1", "FOO2", "FOO3"}, defaultVal: "BAR", want: "VAL1"},
			{name: "second", envs: map[string]string{"FOO2": "VAL2", "FOO3": "VAL3"}, keys: []string{"FOO1", "FOO2", "FOO3"}, defaultVal: "BAR", want: "VAL2"},
			{name: "empty", envs: map[string]string{"FOO": ""}, keys: []string{"FOO"}, defaultVal: "BAR", want: ""},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				for k, v := range tt.envs {
					t.Setenv(k, v)
				}
				if val := StringEnv(tt.defaultVal, tt.keys...); val != tt.want {
					t.Errorf("val = %q, want %q", val, tt.want)
				}
			})
		}
	})

	t.Run("string_slice_env", func(t *testing.T) {
		tests := []struct {
			name       string
			envs       map[string]string
			keys       []string
			defaultVal []string
			want       string
		}{
			{name: "default", envs: nil, keys: []string{"FOO"}, defaultVal: []string{"BAR"}, want: "BAR"},
			{name: "first", envs: map[string]string{"FOO1": "VAL1", "FOO2": "VAL2", "FOO3": "VAL3"}, keys: []string{"FOO1", "FOO2", "FOO3"}, defaultVal: []string{"BAR"}, want: "VAL1"},
			{name: "second", envs: map[string]string{"FOO2": "VAL2", "FOO3": "VAL3"}, keys: []string{"FOO1", "FOO2", "FOO3"}, defaultVal: []string{"BAR"}, want: "VAL2"},
			{name: "empty", envs: map[string]string{"FOO": ""}, keys: []string{"FOO"}, defaultVal: []string{"BAR"}, want: ""},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				for k, v := range tt.envs {
					t.Setenv(k, v)
				}
				val := StringSliceEnv(tt.defaultVal, tt.keys...)
				if len(val) != 1 || val[0] != tt.want {
					t.Errorf("val = %v, want %v", val, []string{tt.want})
				}
			})
		}
	})

	t.Run("int_env", func(t *testing.T) {
		tests := []struct {
			name       string
			envs       map[string]string
			keys       []string
			defaultVal int
			want       int
		}{
			{name: "default", envs: nil, keys: []string{"FOO"}, defaultVal: 5, want: 5},
			{name: "first", envs: map[string]string{"FOO1": "1", "FOO2": "2", "FOO3": "3"}, keys: []string{"FOO1", "FOO2", "FOO3"}, defaultVal: 5, want: 1},
			{name: "second", envs: map[string]string{"FOO2": "2", "FOO3": "3"}, keys: []string{"FOO1", "FOO2", "FOO3"}, defaultVal: 5, want: 2},
			{name: "wrong_type", envs: map[string]string{"FOO": "BAR"}, keys: []string{"FOO"}, defaultVal: 5, want: 5},
			{name: "empty", envs: map[string]string{"FOO": ""}, keys: []string{"FOO"}, defaultVal: 5, want: 5},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				for k, v := range tt.envs {
					t.Setenv(k, v)
				}
				if val := IntEnv(tt.defaultVal, tt.keys...); val != tt.want {
					t.Errorf("val = %d, want %d", val, tt.want)
				}
			})
		}
	})

	t.Run("float_env", func(t *testing.T) {
		tests := []struct {
			name       string
			envs       map[string]string
			keys       []string
			defaultVal float64
			want       float64
		}{
			{name: "default", envs: nil, keys: []string{"FOO"}, defaultVal: 0.5, want: 0.5},
			{name: "first", envs: map[string]string{"FOO1": "1.1", "FOO2": "2.2", "FOO3": "3.3"}, keys: []string{"FOO1", "FOO2", "FOO3"}, defaultVal: 0.5, want: 1.1},
			{name: "second", envs: map[string]string{"FOO2": "2.2", "FOO3": "3.3"}, keys: []string{"FOO1", "FOO2", "FOO3"}, defaultVal: 0.5, want: 2.2},
			{name: "wrong_type", envs: map[string]string{"FOO": "BAR"}, keys: []string{"FOO"}, defaultVal: 0.5, want: 0.5},
			{name: "empty", envs: map[string]string{"FOO": ""}, keys: []string{"FOO"}, defaultVal: 0.5, want: 0.5},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				for k, v := range tt.envs {
					t.Setenv(k, v)
				}
				if val := FloatEnv(tt.defaultVal, tt.keys...); val != tt.want {
					t.Errorf("val = %f, want %f", val, tt.want)
				}
			})
		}
	})

	t.Run("bool_env", func(t *testing.T) {
		tests := []struct {
			name       string
			envs       map[string]string
			keys       []string
			defaultVal bool
			want       bool
		}{
			{name: "default", envs: nil, keys: []string{"FOO"}, defaultVal: true, want: true},
			{name: "first", envs: map[string]string{"FOO1": "true", "FOO2": "false", "FOO3": "false"}, keys: []string{"FOO1", "FOO2", "FOO3"}, defaultVal: true, want: true},
			{name: "second", envs: map[string]string{"FOO2": "true", "FOO3": "false"}, keys: []string{"FOO1", "FOO2", "FOO3"}, defaultVal: true, want: true},
			{name: "empty", envs: map[string]string{"FOO": ""}, keys: []string{"FOO"}, defaultVal: false, want: false},
			{name: "wrong_type", envs: map[string]string{"FOO": "BAR"}, keys: []string{"FOO"}, defaultVal: false, want: false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				for k, v := range tt.envs {
					t.Setenv(k, v)
				}
				if val := BoolEnv(tt.defaultVal, tt.keys...); val != tt.want {
					t.Errorf("val = %t, want %t", val, tt.want)
				}
			})
		}
	})

	t.Run("duration_env", func(t *testing.T) {
		tests := []struct {
			name       string
			envs       map[string]string
			keys       []string
			defaultVal time.Duration
			want       time.Duration
		}{
			{name: "default", envs: nil, keys: []string{"FOO"}, defaultVal: 1 * time.Hour, want: 1 * time.Hour},
			{name: "first", envs: map[string]string{"FOO1": "2h", "FOO2": "3h", "FOO3": "4h"}, keys: []string{"FOO1", "FOO2", "FOO3"}, defaultVal: 1 * time.Hour, want: 2 * time.Hour},
			{name: "second", envs: map[string]string{"FOO2": "3h", "FOO3": "4h"}, keys: []string{"FOO1", "FOO2", "FOO3"}, defaultVal: 1 * time.Hour, want: 3 * time.Hour},
			{name: "wrong_type", envs: map[string]string{"FOO": "BAR"}, keys: []string{"FOO"}, defaultVal: 1 * time.Hour, want: 1 * time.Hour},
			{name: "empty", envs: map[string]string{"FOO": ""}, keys: []string{"FOO"}, defaultVal: 1 * time.Hour, want: 1 * time.Hour},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				for k, v := range tt.envs {
					t.Setenv(k, v)
				}
				if val := DurationEnv(tt.defaultVal, tt.keys...); val != tt.want {
					t.Errorf("val = %v, want %v", val, tt.want)
				}
			})
		}
	})
}
