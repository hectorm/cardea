package ansi

import "unicode/utf8"

type state int

const (
	stateStart state = iota
	stateGotEsc
	stateIgnoreNextChar
	stateInCsi
	stateInOsc
	stateInOscGotEsc
	stateNeedSt
	stateNeedStGotEsc
)

const (
	c1CSI = 0x9b // Control Sequence Introducer
	c1OSC = 0x9d // Operating System Command
	c1DCS = 0x90 // Device Control String
	c1SOS = 0x98 // Start of String
	c1PM  = 0x9e // Privacy Message
	c1APC = 0x9f // Application Program Command
	c1ST  = 0x9c // String Terminator
)

func isEscapeRune(r rune) bool {
	switch r {
	case 0x1b, c1CSI, c1OSC, c1DCS, c1SOS, c1PM, c1APC:
		return true
	default:
		return false
	}
}

func findEscapeRune(b []byte) int {
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if isEscapeRune(r) {
			return i
		}
		i += size
	}
	return -1
}

func consumeANSI(b []byte) int {
	st := stateStart
	i := 0
	for i < len(b) {
		r, size := utf8.DecodeRune(b[i:])

		switch st {
		case stateStart:
			switch r {
			case 0x1b:
				st = stateGotEsc
			case c1CSI:
				st = stateInCsi
			case c1OSC:
				st = stateInOsc
			case c1DCS, c1SOS, c1PM, c1APC:
				st = stateNeedSt
			default:
				return i
			}

		case stateGotEsc:
			switch r {
			case '[':
				st = stateInCsi
			case ' ', '#', '%', '(', ')', '*', '+', '.', '/':
				st = stateIgnoreNextChar
			case ']':
				st = stateInOsc
			case 'P', 'X', '^', '_':
				st = stateNeedSt
			default:
				st = stateStart
			}

		case stateIgnoreNextChar:
			st = stateStart

		case stateInCsi:
			if r >= 0x40 && r <= 0x7e {
				st = stateStart
			}

		case stateInOsc:
			switch r {
			case 0x1b:
				st = stateInOscGotEsc
			case c1ST, 0x07:
				st = stateStart
			}

		case stateInOscGotEsc:
			if r == '\\' {
				st = stateStart
			} else {
				st = stateInOsc
			}

		case stateNeedSt:
			switch r {
			case 0x1b:
				st = stateNeedStGotEsc
			case c1ST:
				st = stateStart
			}

		case stateNeedStGotEsc:
			if r == '\\' {
				st = stateStart
			} else {
				st = stateNeedSt
			}
		}

		i += size
	}
	return len(b)
}

// StripEscapes removes ANSI escape sequences as defined in ECMA-48 (5th edition).
// https://ecma-international.org/publications-and-standards/standards/ecma-48/
func StripEscapes(b []byte) []byte {
	idx := findEscapeRune(b)
	if idx == -1 {
		return b
	}

	result := make([]byte, 0, len(b))
	for idx != -1 {
		result = append(result, b[:idx]...)
		b = b[idx:]
		consumed := consumeANSI(b)
		b = b[consumed:]
		idx = findEscapeRune(b)
	}

	result = append(result, b...)
	return result
}
