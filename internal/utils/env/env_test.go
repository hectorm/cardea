package env

import (
	"testing"
	"time"
)

func TestEnv(t *testing.T) {
	t.Run("string_env_default", func(t *testing.T) {
		if val := StringEnv("BAR", "FOO"); val != "BAR" {
			t.Errorf("val = \"%s\", want \"%s\"", val, "BAR")
		}
	})

	t.Run("string_env_first", func(t *testing.T) {
		t.Setenv("FOO1", "VAL1")
		t.Setenv("FOO2", "VAL2")
		t.Setenv("FOO3", "VAL3")
		if val := StringEnv("BAR", "FOO1", "FOO2", "FOO3"); val != "VAL1" {
			t.Errorf("val = \"%s\", want \"%s\"", val, "VAL1")
		}
	})

	t.Run("string_env_second", func(t *testing.T) {
		t.Setenv("FOO2", "VAL2")
		t.Setenv("FOO3", "VAL3")
		if val := StringEnv("BAR", "FOO1", "FOO2", "FOO3"); val != "VAL2" {
			t.Errorf("val = \"%s\", want \"%s\"", val, "VAL2")
		}
	})

	t.Run("string_env_empty", func(t *testing.T) {
		t.Setenv("FOO", "")
		if val := StringEnv("BAR", "FOO"); val != "" {
			t.Errorf("val = \"%s\", want \"%s\"", val, "")
		}
	})

	t.Run("string_slice_env_default", func(t *testing.T) {
		if val := StringSliceEnv([]string{"BAR"}, "FOO"); len(val) != 1 || val[0] != "BAR" {
			t.Errorf("val = %v, want %v", val, []string{"BAR"})
		}
	})

	t.Run("string_slice_env_first", func(t *testing.T) {
		t.Setenv("FOO1", "VAL1")
		t.Setenv("FOO2", "VAL2")
		t.Setenv("FOO3", "VAL3")
		if val := StringSliceEnv([]string{"BAR"}, "FOO1", "FOO2", "FOO3"); len(val) != 1 || val[0] != "VAL1" {
			t.Errorf("val = %v, want %v", val, []string{"VAL1"})
		}
	})

	t.Run("string_slice_env_second", func(t *testing.T) {
		t.Setenv("FOO2", "VAL2")
		t.Setenv("FOO3", "VAL3")
		if val := StringSliceEnv([]string{"BAR"}, "FOO1", "FOO2", "FOO3"); len(val) != 1 || val[0] != "VAL2" {
			t.Errorf("val = %v, want %v", val, []string{"VAL2"})
		}
	})

	t.Run("string_slice_env_empty", func(t *testing.T) {
		t.Setenv("FOO", "")
		if val := StringSliceEnv([]string{"BAR"}, "FOO"); len(val) != 1 || val[0] != "" {
			t.Errorf("val = %v, want %v", val, []string{""})
		}
	})

	t.Run("int_env_default", func(t *testing.T) {
		if val := IntEnv(5, "FOO"); val != 5 {
			t.Errorf("val = %d, want %d", val, 5)
		}
	})

	t.Run("int_env_first", func(t *testing.T) {
		t.Setenv("FOO1", "1")
		t.Setenv("FOO2", "2")
		t.Setenv("FOO3", "3")
		if val := IntEnv(5, "FOO1", "FOO2", "FOO3"); val != 1 {
			t.Errorf("val = %d, want %d", val, 1)
		}
	})

	t.Run("int_env_second", func(t *testing.T) {
		t.Setenv("FOO2", "2")
		t.Setenv("FOO3", "3")
		if val := IntEnv(5, "FOO1", "FOO2", "FOO3"); val != 2 {
			t.Errorf("val = %d, want %d", val, 2)
		}
	})

	t.Run("int_env_wrong_type", func(t *testing.T) {
		t.Setenv("FOO", "BAR")
		if val := IntEnv(5, "FOO"); val != 5 {
			t.Errorf("val = %d, want %d", val, 5)
		}
	})

	t.Run("int_env_empty", func(t *testing.T) {
		t.Setenv("FOO", "")
		if val := IntEnv(5, "FOO"); val != 5 {
			t.Errorf("val = %d, want %d", val, 5)
		}
	})

	t.Run("float_env_default", func(t *testing.T) {
		if val := FloatEnv(0.5, "FOO"); val != 0.5 {
			t.Errorf("val = %f, want %f", val, 0.5)
		}
	})

	t.Run("float_env_first", func(t *testing.T) {
		t.Setenv("FOO1", "1.1")
		t.Setenv("FOO2", "2.2")
		t.Setenv("FOO3", "3.3")
		if val := FloatEnv(0.5, "FOO1", "FOO2", "FOO3"); val != 1.1 {
			t.Errorf("val = %f, want %f", val, 1.1)
		}
	})

	t.Run("float_env_second", func(t *testing.T) {
		t.Setenv("FOO2", "2.2")
		t.Setenv("FOO3", "3.3")
		if val := FloatEnv(0.5, "FOO1", "FOO2", "FOO3"); val != 2.2 {
			t.Errorf("val = %f, want %f", val, 2.2)
		}
	})

	t.Run("float_env_wrong_type", func(t *testing.T) {
		t.Setenv("FOO", "BAR")
		if val := FloatEnv(0.5, "FOO"); val != 0.5 {
			t.Errorf("val = %f, want %f", val, 0.5)
		}
	})

	t.Run("float_env_empty", func(t *testing.T) {
		t.Setenv("FOO", "")
		if val := FloatEnv(0.5, "FOO"); val != 0.5 {
			t.Errorf("val = %f, want %f", val, 0.5)
		}
	})

	t.Run("bool_env_default", func(t *testing.T) {
		if val := BoolEnv(true, "FOO"); !val {
			t.Errorf("val = %t, want %t", val, true)
		}
	})

	t.Run("bool_env_first", func(t *testing.T) {
		t.Setenv("FOO1", "true")
		t.Setenv("FOO2", "false")
		t.Setenv("FOO3", "false")
		if val := BoolEnv(true, "FOO1", "FOO2", "FOO3"); !val {
			t.Errorf("val = %t, want %t", val, true)
		}
	})

	t.Run("bool_env_second", func(t *testing.T) {
		t.Setenv("FOO2", "true")
		t.Setenv("FOO3", "false")
		if val := BoolEnv(true, "FOO1", "FOO2", "FOO3"); !val {
			t.Errorf("val = %t, want %t", val, true)
		}
	})

	t.Run("bool_env_empty", func(t *testing.T) {
		t.Setenv("FOO", "")
		if val := BoolEnv(false, "FOO"); val {
			t.Errorf("val = %t, want %t", val, false)
		}
	})

	t.Run("bool_env_wrong_type", func(t *testing.T) {
		t.Setenv("FOO", "BAR")
		if val := BoolEnv(false, "FOO"); val {
			t.Errorf("val = %t, want %t", val, false)
		}
	})

	t.Run("duration_env_default", func(t *testing.T) {
		if val := DurationEnv(1*time.Hour, "FOO"); val != 1*time.Hour {
			t.Errorf("val = %d, want %d", val, 1*time.Hour)
		}
	})

	t.Run("duration_env_first", func(t *testing.T) {
		t.Setenv("FOO1", "2h")
		t.Setenv("FOO2", "3h")
		t.Setenv("FOO3", "4h")
		if val := DurationEnv(1*time.Hour, "FOO1", "FOO2", "FOO3"); val != 2*time.Hour {
			t.Errorf("val = %d, want %d", val, 2*time.Hour)
		}
	})

	t.Run("duration_env_second", func(t *testing.T) {
		t.Setenv("FOO2", "3h")
		t.Setenv("FOO3", "4h")
		if val := DurationEnv(1*time.Hour, "FOO1", "FOO2", "FOO3"); val != 3*time.Hour {
			t.Errorf("val = %d, want %d", val, 3*time.Hour)
		}
	})

	t.Run("duration_env_wrong_type", func(t *testing.T) {
		t.Setenv("FOO", "BAR")
		if val := DurationEnv(1*time.Hour, "FOO"); val != 1*time.Hour {
			t.Errorf("val = %d, want %d", val, 1*time.Hour)
		}
	})

	t.Run("duration_env_empty", func(t *testing.T) {
		t.Setenv("FOO", "")
		if val := DurationEnv(1*time.Hour, "FOO"); val != 1*time.Hour {
			t.Errorf("val = %d, want %d", val, 1*time.Hour)
		}
	})
}
