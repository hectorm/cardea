package ansi

import "testing"

func TestStripEscapes(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		// Plain text
		{"empty string", "", ""},
		{"plain text", "plain text", "plain text"},
		{"not an escape sequence", "[0m not an escape", "[0m not an escape"},
		{"UTF-8 preserved", "日本語テスト", "日本語テスト"},

		// CSI sequences (ESC [)
		{"SGR reset", "\x1b[0m", ""},
		{"SGR foreground color", "\x1b[31mred\x1b[0m", "red"},
		{"SGR 256 color", "\x1b[38;5;196m256 color\x1b[0m", "256 color"},
		{"SGR RGB color", "\x1b[38;2;255;0;0mRGB color\x1b[0m", "RGB color"},
		{"SGR multiple attributes", "\x1b[1;4;31mstyled\x1b[0m", "styled"},
		{"SGR long params", "\x1b[1;2;3;4;5;6;7;8;9;10mlong params", "long params"},
		{"CSI cursor position", "\x1b[10;20Hposition", "position"},
		{"CSI cursor up", "\x1b[5Amoved up", "moved up"},
		{"CSI cursor down", "\x1b[5Bmoved down", "moved down"},
		{"CSI cursor forward", "\x1b[5Cmoved forward", "moved forward"},
		{"CSI cursor back", "\x1b[5Dmoved back", "moved back"},
		{"CSI erase display", "\x1b[2Jclear screen", "clear screen"},
		{"CSI erase line", "\x1b[Kclear line", "clear line"},
		{"CSI erase to end of line", "\x1b[0Kclear to end", "clear to end"},
		{"CSI show cursor", "\x1b[?25hvisible", "visible"},
		{"CSI hide cursor", "\x1b[?25linvisible", "invisible"},
		{"CSI alternate screen", "\x1b[?1049haltscreen\x1b[?1049l", "altscreen"},
		{"CSI private final byte", "\x1b[0qled state", "led state"},
		{"CSI with space intermediate", "\x1b[ qcursor style", "cursor style"},
		{"CSI soft reset", "\x1b[!preset", "reset"},

		// C1 control codes (8-bit)
		{"C1 CSI", "\u009B31mC1 red\u009B0m", "C1 red"},
		{"C1 OSC", "\u009D0;title\x07text", "text"},
		{"C1 DCS with C1 ST", "\u0090dcs content\u009Ctext", "text"},
		{"C1 SOS with C1 ST", "\u0098sos content\u009Ctext", "text"},
		{"C1 PM with C1 ST", "\u009Epm content\u009Ctext", "text"},
		{"C1 APC with C1 ST", "\u009Fapc content\u009Ctext", "text"},
		{"C1 ST terminator", "\x1b]0;title\u009Ctext", "text"},

		// OSC sequences (ESC ])
		{"OSC window title with BEL", "\x1b]0;title\x07text", "text"},
		{"OSC window title with ST", "\x1b]0;title\x1b\\text", "text"},
		{"OSC hyperlink", "\x1b]8;;https://example.com\x07link\x1b]8;;\x07", "link"},
		{"OSC with semicolons", "\x1b]0;a;b;c\x07text", "text"},

		// String sequences (DCS, SOS, PM, APC)
		{"DCS with ST", "\x1bPdcs content\x1b\\text", "text"},
		{"SOS with ST", "\x1bXsos content\x1b\\text", "text"},
		{"PM with ST", "\x1b^pm content\x1b\\text", "text"},
		{"APC with ST", "\x1b_apc content\x1b\\text", "text"},
		{"DCS with embedded ESC", "\x1bPdcs\x1bXmore\x1b\\text", "text"},
		{"OSC with embedded ESC", "\x1b]0;title\x1bXmore\x07text", "text"},

		// Two-byte escape sequences
		{"keypad application mode", "\x1b=keypad", "keypad"},
		{"keypad numeric mode", "\x1b>numeric", "numeric"},
		{"keypad mode toggle", "\x1b=app\x1b>num", "appnum"},
		{"index (IND)", "\x1bDindexed", "indexed"},
		{"next line (NEL)", "\x1bEnext line", "next line"},
		{"reverse index (RI)", "\x1bMreverse", "reverse"},
		{"charset G0 designate", "\x1b(Bcharset", "charset"},
		{"charset G1 designate", "\x1b)0charset", "charset"},
		{"DEC save cursor", "\x1b7saved", "saved"},
		{"DEC restore cursor", "\x1b8restored", "restored"},
		{"DEC alignment test", "\x1b#8alignment", "alignment"},
		{"DEC double-height top", "\x1b#3double", "double"},
		{"DEC double-height bottom", "\x1b#4double", "double"},
		{"DEC single-width", "\x1b#5single", "single"},
		{"DEC double-width", "\x1b#6double", "double"},

		// UTF-8 content with escapes
		{"UTF-8 with SGR", "\x1b[31m日本語\x1b[0m", "日本語"},
		{"UTF-8 with multiple escapes", "\x1b[1m中文\x1b[0m\x1b[32m한글\x1b[0m", "中文한글"},
		{"emoji preserved", "\x1b[31m🎉\x1b[0m", "🎉"},

		// Edge cases
		{"escape at start", "\x1b[31mred text", "red text"},
		{"escape at end", "text\x1b[31m", "text"},
		{"escape in middle", "before\x1b[31mred\x1b[0mafter", "beforeredafter"},
		{"consecutive escapes", "\x1b[31m\x1b[32m\x1b[33m", ""},
		{"trailing ESC", "text\x1b", "text"},
		{"trailing ESC [", "text\x1b[", "text"},
		{"incomplete CSI no final", "text\x1b[31", "text"},
		{"incomplete OSC no terminator", "text\x1b]0;title", "text"},
		{"just ESC", "\x1b", ""},
		{"multiple trailing ESC", "text\x1b\x1b\x1b", "text"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(StripEscapes([]byte(tt.input)))
			if got != tt.want {
				t.Errorf("StripEscapes(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
