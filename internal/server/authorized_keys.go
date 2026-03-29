package server

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hectorm/cardea/internal/timewindow"
)

const (
	maxInputSize            = 256 * 1024 * 1024 // 256MB
	maxLineLength           = 16 * 1024 * 1024  // 16MB
	maxPermitConnectLength  = 1024
	maxPermitTCPLength      = 512
	maxPermitSocketLength   = 512
	maxMacroExpansionDepth  = 10
	maxMacroExpansionTokens = 256 * 1024
)

type AuthorizedKeyOptions struct {
	PermitConnects      []PermitConnect        `json:"permit_connects"`
	PermitOpens         []PermitTCP            `json:"permit_opens"`
	PermitListens       []PermitTCP            `json:"permit_listens"`
	PermitSocketOpens   []PermitSocket         `json:"permit_socket_opens"`
	PermitSocketListens []PermitSocket         `json:"permit_socket_listens"`
	Environments        []Environment          `json:"environments"`
	Froms               []string               `json:"froms"`
	StartTime           *time.Time             `json:"start_time"`
	ExpiryTime          *time.Time             `json:"expiry_time"`
	TimeWindow          *timewindow.TimeWindow `json:"time_window"`
	Command             string                 `json:"command"`
	NoPortForwarding    bool                   `json:"no_port_forwarding"`
	NoSocketForwarding  bool                   `json:"no_socket_forwarding"`
	NoPty               bool                   `json:"no_pty"`
	NoRecording         bool                   `json:"no_recording"`
	Comment             string                 `json:"comment"`
}

type PermitConnect struct {
	User string `json:"user"`
	Host string `json:"host"`
	Port string `json:"port"`
}

type PermitTCP struct {
	Host string `json:"host"`
	Port string `json:"port"`
}

type PermitSocket struct {
	Path string `json:"path"`
}

type Environment struct {
	Sign  string `json:"sign"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

func (srv *Server) newAuthorizedKeysDB(path string) (map[string][]*AuthorizedKeyOptions, error) {
	path = filepath.Clean(path)

	if f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600); err == nil {
		_ = f.Close()
	} else if !os.IsExist(err) {
		return nil, err
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return parseAuthorizedKeys(content)
}

func parseAuthorizedKeys(content []byte) (map[string][]*AuthorizedKeyOptions, error) {
	if len(content) > maxInputSize {
		return nil, fmt.Errorf("authorized_keys file exceeds maximum size of %d bytes", maxInputSize)
	}

	authKeysDB := make(map[string][]*AuthorizedKeyOptions)

	logWarning := func(w preprocessWarning) {
		if w.context != "" {
			slog.Warn("authorized_keys file parse", "line", w.line, "reason", w.message, "context", w.context)
		} else {
			slog.Warn("authorized_keys file parse", "line", w.line, "reason", w.message)
		}
	}

	preprocess(string(content), func(line preprocessedLine) {
		var keys []string
		var keyOpts *AuthorizedKeyOptions

		for _, seg := range line.segments {
			publicKey, comment, segOpts, _, err := ssh.ParseAuthorizedKey(seg)
			if err != nil {
				slog.Warn("authorized_keys file parse", "line", line.line, "reason", err, "context", line.raw)
				return
			}
			if keyOpts == nil {
				if len(segOpts) == 0 {
					slog.Warn("authorized_keys file parse", "line", line.line, "reason", "missing options", "context", line.raw)
					return
				}
				keyOpts, err = parseOptions(segOpts)
				if err != nil {
					slog.Warn("authorized_keys file parse", "line", line.line, "reason", err, "context", line.raw)
					return
				}
				keyOpts.Comment = comment
			} else if len(segOpts) > 0 {
				slog.Warn("authorized_keys file parse", "line", line.line, "reason", "unexpected options", "context", line.raw)
				return
			}
			keys = append(keys, string(publicKey.Marshal()))
		}

		for _, key := range keys {
			authKeysDB[key] = append(authKeysDB[key], keyOpts)
		}
	}, logWarning)

	return authKeysDB, nil
}

func parseOptions(opts []string) (*AuthorizedKeyOptions, error) {
	authKeyOpts := &AuthorizedKeyOptions{}

	for _, opt := range opts {
		name, val, ok := splitOption(opt)
		if !ok {
			return nil, fmt.Errorf("malformed option: %s", opt)
		}

		switch name {
		case "permitconnect":
			for v := range strings.SplitSeq(val, ",") {
				permitconnect, err := parsePermitConnect(strings.TrimSpace(v))
				if err != nil {
					return nil, fmt.Errorf("invalid permitconnect: %w", err)
				}
				authKeyOpts.PermitConnects = append(authKeyOpts.PermitConnects, *permitconnect)
			}
		case "permitopen":
			for v := range strings.SplitSeq(val, ",") {
				permitopen, err := parsePermitTCP(strings.TrimSpace(v))
				if err != nil {
					return nil, fmt.Errorf("invalid permitopen: %w", err)
				}
				authKeyOpts.PermitOpens = append(authKeyOpts.PermitOpens, *permitopen)
			}
		case "permitlisten":
			for v := range strings.SplitSeq(val, ",") {
				permitlisten, err := parsePermitTCP(strings.TrimSpace(v))
				if err != nil {
					return nil, fmt.Errorf("invalid permitlisten: %w", err)
				}
				authKeyOpts.PermitListens = append(authKeyOpts.PermitListens, *permitlisten)
			}
		case "permitsocketopen":
			permitsocketopen, err := parsePermitSocket(strings.TrimSpace(val))
			if err != nil {
				return nil, fmt.Errorf("invalid permitsocketopen: %w", err)
			}
			authKeyOpts.PermitSocketOpens = append(authKeyOpts.PermitSocketOpens, *permitsocketopen)
		case "permitsocketlisten":
			permitsocketlisten, err := parsePermitSocket(strings.TrimSpace(val))
			if err != nil {
				return nil, fmt.Errorf("invalid permitsocketlisten: %w", err)
			}
			authKeyOpts.PermitSocketListens = append(authKeyOpts.PermitSocketListens, *permitsocketlisten)
		case "environment":
			environment, err := parseEnvironment(val)
			if err != nil {
				return nil, fmt.Errorf("invalid environment: %w", err)
			}
			authKeyOpts.Environments = append(authKeyOpts.Environments, *environment)
		case "from":
			for v := range strings.SplitSeq(val, ",") {
				from, err := parseFrom(strings.TrimSpace(v))
				if err != nil {
					return nil, fmt.Errorf("invalid from: %w", err)
				}
				authKeyOpts.Froms = append(authKeyOpts.Froms, from)
			}
		case "start-time":
			t, err := parseTimespec(val)
			if err != nil {
				return nil, fmt.Errorf("invalid start-time: %w", err)
			}
			if authKeyOpts.StartTime == nil || t.After(*authKeyOpts.StartTime) {
				authKeyOpts.StartTime = &t
			}
		case "expiry-time":
			t, err := parseTimespec(val)
			if err != nil {
				return nil, fmt.Errorf("invalid expiry-time: %w", err)
			}
			if authKeyOpts.ExpiryTime == nil || t.Before(*authKeyOpts.ExpiryTime) {
				authKeyOpts.ExpiryTime = &t
			}
		case "time-window":
			tw, err := timewindow.Parse(val)
			if err != nil {
				return nil, fmt.Errorf("invalid time-window: %w", err)
			}
			if authKeyOpts.TimeWindow != nil {
				authKeyOpts.TimeWindow.Windows = append(authKeyOpts.TimeWindow.Windows, tw.Windows...)
			} else {
				authKeyOpts.TimeWindow = tw
			}
		case "command":
			authKeyOpts.Command = val
		case "port-forwarding":
			authKeyOpts.NoPortForwarding = false
		case "no-port-forwarding":
			authKeyOpts.NoPortForwarding = true
		case "socket-forwarding":
			authKeyOpts.NoSocketForwarding = false
		case "no-socket-forwarding":
			authKeyOpts.NoSocketForwarding = true
		case "pty":
			authKeyOpts.NoPty = false
		case "no-pty":
			authKeyOpts.NoPty = true
		case "restrict":
			authKeyOpts.NoPortForwarding = true
			authKeyOpts.NoSocketForwarding = true
			authKeyOpts.NoPty = true
		case "recording":
			authKeyOpts.NoRecording = false
		case "no-recording":
			authKeyOpts.NoRecording = true
		}
	}

	if len(authKeyOpts.PermitConnects) == 0 {
		return nil, fmt.Errorf("missing required 'permitconnect' option")
	}

	if len(authKeyOpts.PermitOpens) == 0 {
		authKeyOpts.PermitOpens = []PermitTCP{
			{Host: "localhost", Port: "1-65535"},
			{Host: "127.0.0.1/8", Port: "1-65535"},
			{Host: "::1/128", Port: "1-65535"},
		}
	}

	return authKeyOpts, nil
}

func splitOption(opt string) (name, value string, ok bool) {
	name, quoted, hasValue := strings.Cut(opt, "=")
	if !hasValue {
		return name, "", true
	}

	if len(quoted) < 2 || quoted[0] != '"' {
		return "", "", false
	}

	var b strings.Builder
	for i := 1; i < len(quoted); i++ {
		switch quoted[i] {
		case '\\':
			if i+1 < len(quoted) && quoted[i+1] == '"' {
				b.WriteByte('"')
				i++
			} else {
				b.WriteByte('\\')
			}
		case '"':
			if i != len(quoted)-1 {
				return "", "", false // garbage after closing quote
			}
			return name, b.String(), true
		default:
			b.WriteByte(quoted[i])
		}
	}
	return "", "", false // no closing quote
}

func parsePermitConnect(permitconnect string) (*PermitConnect, error) {
	if permitconnect != "" && len(permitconnect) <= maxPermitConnectLength {
		// Try format <user>@<host>[:<port>]
		if i := strings.LastIndex(permitconnect, "@"); i != -1 {
			user, addr := permitconnect[:i], permitconnect[i+1:]
			host, port, err := net.SplitHostPort(addr)
			if err == nil && user != "" && host != "" && port != "" {
				return &PermitConnect{User: user, Host: host, Port: port}, nil
			} else if user != "" && addr != "" {
				host := strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]")
				if ip := net.ParseIP(host); ip != nil {
					return &PermitConnect{User: user, Host: ip.String(), Port: "22"}, nil
				} else if host != "" && !strings.Contains(host, ":") {
					return &PermitConnect{User: user, Host: host, Port: "22"}, nil
				}
			}
		}

		// Try format <user>+<host>[+<port>]
		if parts := strings.Split(permitconnect, "+"); len(parts) == 3 {
			user, host, port := parts[0], parts[1], parts[2]
			host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
			_, _, err := net.SplitHostPort(net.JoinHostPort(host, port))
			if err == nil && user != "" && host != "" && port != "" {
				return &PermitConnect{User: user, Host: host, Port: port}, nil
			}
		} else if len(parts) == 2 {
			user, host := parts[0], parts[1]
			host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
			if user != "" && host != "" {
				if ip := net.ParseIP(host); ip != nil {
					return &PermitConnect{User: user, Host: ip.String(), Port: "22"}, nil
				} else if host != "" && !strings.Contains(host, ":") {
					return &PermitConnect{User: user, Host: host, Port: "22"}, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("expected <user>@<host>[:<port>] or <user>+<host>[+<port>], got %s", permitconnect)
}

func parsePermitTCP(s string) (*PermitTCP, error) {
	if s == "" {
		return nil, fmt.Errorf("empty value")
	}
	if len(s) > maxPermitTCPLength {
		return nil, fmt.Errorf("exceeds maximum length of %d", maxPermitTCPLength)
	}

	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" || port == "" {
		return nil, fmt.Errorf("expected <host>:<port>, got %s", s)
	}

	return &PermitTCP{Host: host, Port: port}, nil
}

func parsePermitSocket(s string) (*PermitSocket, error) {
	if s == "" {
		return nil, fmt.Errorf("empty value")
	}
	if len(s) > maxPermitSocketLength {
		return nil, fmt.Errorf("exceeds maximum length of %d", maxPermitSocketLength)
	}

	if s == "*" {
		return &PermitSocket{Path: s}, nil
	}

	s = path.Clean(s)
	return &PermitSocket{Path: s}, nil
}

func parseEnvironment(s string) (*Environment, error) {
	if len(s) > 0 && (s[0] == '+' || s[0] == '-') {
		pattern := s[1:]
		if pattern == "" {
			return nil, fmt.Errorf("empty pattern")
		}
		for _, c := range pattern {
			if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '*' || c == '?' || c == '[' || c == ']') {
				return nil, fmt.Errorf("pattern %q contains disallowed characters", pattern)
			}
		}
		if _, err := path.Match(pattern, ""); err != nil {
			return nil, fmt.Errorf("pattern %q is malformed: %w", pattern, err)
		}
		return &Environment{Sign: string(s[0]), Name: pattern}, nil
	}

	i := strings.IndexByte(s, '=')
	if i < 1 {
		return nil, fmt.Errorf("expected NAME=value, got %s", s)
	}

	name := s[:i]
	for _, c := range name {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return nil, fmt.Errorf("variable name %q contains disallowed characters", name)
		}
	}

	return &Environment{Name: name, Value: s[i+1:]}, nil
}

func parseFrom(s string) (string, error) {
	if s == "" {
		return "", fmt.Errorf("empty value")
	}

	return s, nil
}

func parseTimespec(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, fmt.Errorf("empty timespec")
	}

	isUTC := false
	if strings.HasSuffix(strings.ToUpper(s), "Z") {
		isUTC = true
		s = s[:len(s)-1]
	}

	loc := time.Local
	if isUTC {
		loc = time.UTC
	}

	var year, month, day, hour, minute, second int

	switch len(s) {
	case 8: // YYYYMMDD
		n, err := fmt.Sscanf(s, "%04d%02d%02d", &year, &month, &day)
		if err != nil || n != 3 {
			return time.Time{}, fmt.Errorf("invalid date format %q", s)
		}
	case 12: // YYYYMMDDHHMM
		n, err := fmt.Sscanf(s, "%04d%02d%02d%02d%02d", &year, &month, &day, &hour, &minute)
		if err != nil || n != 5 {
			return time.Time{}, fmt.Errorf("invalid datetime format %q", s)
		}
	case 14: // YYYYMMDDHHMMSS
		n, err := fmt.Sscanf(s, "%04d%02d%02d%02d%02d%02d", &year, &month, &day, &hour, &minute, &second)
		if err != nil || n != 6 {
			return time.Time{}, fmt.Errorf("invalid datetime format %q", s)
		}
	default:
		return time.Time{}, fmt.Errorf("invalid timespec length: expected 8, 9, 12, 13, 14, or 15 characters")
	}

	// Validate ranges
	if month < 1 || month > 12 {
		return time.Time{}, fmt.Errorf("invalid month %d", month)
	}
	if day < 1 || day > 31 {
		return time.Time{}, fmt.Errorf("invalid day %d", day)
	}
	if hour < 0 || hour > 23 {
		return time.Time{}, fmt.Errorf("invalid hour %d", hour)
	}
	if minute < 0 || minute > 59 {
		return time.Time{}, fmt.Errorf("invalid minute %d", minute)
	}
	if second < 0 || second > 59 {
		return time.Time{}, fmt.Errorf("invalid second %d", second)
	}

	// Create time and validate the date is real
	t := time.Date(year, time.Month(month), day, hour, minute, second, 0, loc)
	if t.Year() != year || int(t.Month()) != month || t.Day() != day {
		return time.Time{}, fmt.Errorf("invalid date: %04d-%02d-%02d does not exist", year, month, day)
	}

	return t, nil
}

type tokenType uint8

const (
	tokError tokenType = iota
	tokWhitespace
	tokNewline
	tokLineContinuation
	tokOther
	tokIdent
	tokQuoteStart
	tokQuoteEnd
	tokPipe
	tokComment
	tokDefine
)

type token struct {
	start uint32
	end   uint32
	line  uint32
	typ   tokenType
}

func (t token) val(input string) string {
	return input[t.start:t.end]
}

var knownDirectives = []struct {
	name    string
	len     uint32
	tokType tokenType
}{
	{"#define", 7, tokDefine},
}

type lexer struct {
	input   string
	length  uint32
	pos     uint32
	line    uint32
	bol     bool
	inQuote bool
	sentEOF bool
	lastTyp tokenType
	errors  []string
	emitted token
}

func newLexer(input string) *lexer {
	return &lexer{
		input: input,
		// #nosec G115 - bounded by maxInputSize
		length: uint32(len(input)),
		line:   1,
		bol:    true,
	}
}

func (l *lexer) next() (token, bool) {
	if l.pos >= l.length {
		if l.inQuote {
			l.inQuote = false
			l.emitError("unterminated quoted string")
			l.lastTyp = l.emitted.typ
			return l.emitted, true
		}
		// Ensure stream ends with a newline for uniform processing
		if !l.sentEOF && l.lastTyp != tokNewline {
			l.sentEOF = true
			return token{typ: tokNewline, start: l.pos, end: l.pos, line: l.line}, true
		}
		return token{}, false
	}
	l.scanToken()
	l.lastTyp = l.emitted.typ
	return l.emitted, true
}

func (l *lexer) emit(typ tokenType, start, end uint32) {
	l.emitted = token{typ: typ, start: start, end: end, line: l.line}
}

func (l *lexer) emitError(msg string) {
	idx := len(l.errors)
	l.errors = append(l.errors, msg)
	// #nosec G115 - bounded by maxInputSize
	l.emitted = token{typ: tokError, start: uint32(idx), line: l.line}
}

func (l *lexer) errorMsg(tok token) string {
	return l.errors[tok.start]
}

func (l *lexer) peek() byte {
	if l.pos >= l.length {
		return 0
	}
	return l.input[l.pos]
}

func (l *lexer) peekAt(offset uint32) byte {
	if l.pos+offset >= l.length {
		return 0
	}
	return l.input[l.pos+offset]
}

func (l *lexer) scanToken() {
	if l.inQuote {
		l.scanQuotedInner()
		return
	}

	c := l.peek()

	// Line continuation: backslash followed by newline
	if c == '\\' {
		if l.peekAt(1) == '\n' {
			l.emit(tokLineContinuation, l.pos, l.pos)
			l.pos += 2
			l.line++
			l.bol = true
			return
		}
		if l.peekAt(1) == '\r' && l.peekAt(2) == '\n' {
			l.emit(tokLineContinuation, l.pos, l.pos)
			l.pos += 3
			l.line++
			l.bol = true
			return
		}
	}

	// Newline
	if c == '\n' || c == '\r' {
		start := l.pos
		l.pos++
		if c == '\r' && l.peek() == '\n' {
			l.pos++
		}
		l.emit(tokNewline, start, l.pos)
		l.line++
		l.bol = true
		return
	}

	// Directive or comment
	if c == '#' {
		if l.bol {
			// Directives only at beginning of line
			if typ, length := l.matchDirective(); length > 0 {
				l.emit(typ, l.pos, l.pos+length)
				l.pos += length
				l.bol = false
				return
			}
			// BOL comment (includes newline)
			l.scanBOLComment()
			return
		}
		// Inline comment (excludes newline)
		l.scanInlineComment()
		return
	}

	// Whitespace (preserves bol state)
	if l.scanWhitespace() {
		return
	}

	// Identifier
	if l.scanIdent() {
		l.bol = false
		return
	}

	// Quoted string
	if l.scanQuoted() {
		l.bol = false
		return
	}

	// Pipe (only matched outside quoted strings)
	if c == '|' {
		l.emit(tokPipe, l.pos, l.pos+1)
		l.pos++
		l.bol = false
		return
	}

	// NUL byte
	if c == 0 {
		l.emitError("line contains NUL byte")
		l.pos++
		l.bol = false
		return
	}

	// Other character
	l.emit(tokOther, l.pos, l.pos+1)
	l.pos++
	l.bol = false
}

func (l *lexer) scanBOLComment() {
	start := l.pos
	l.pos++ // skip #
	for l.pos < l.length && l.peek() != '\n' && l.peek() != '\r' {
		l.pos++
	}
	// Include trailing newline in comment
	if l.peek() == '\r' {
		l.pos++
	}
	if l.peek() == '\n' {
		l.pos++
	}
	l.emit(tokComment, start, l.pos)
	l.line++
	l.bol = true
}

func (l *lexer) scanInlineComment() {
	start := l.pos
	l.pos++ // skip #
	for l.pos < l.length && l.peek() != '\n' && l.peek() != '\r' {
		l.pos++
	}
	// Do not include trailing newline, it will be a separate tokNewline
	l.emit(tokComment, start, l.pos)
	l.bol = false
}

func (l *lexer) scanWhitespace() bool {
	if l.peek() != ' ' && l.peek() != '\t' {
		return false
	}
	start := l.pos
	for l.pos < l.length && (l.peek() == ' ' || l.peek() == '\t') {
		l.pos++
	}
	l.emit(tokWhitespace, start, l.pos)
	return true
}

func (l *lexer) scanIdent() bool {
	c := l.peek()
	if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '_') {
		return false
	}
	start := l.pos
	l.pos++
	for l.pos < l.length {
		c = l.peek()
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '_' || c >= '0' && c <= '9') {
			break
		}
		l.pos++
	}
	l.emit(tokIdent, start, l.pos)
	return true
}

func (l *lexer) scanQuoted() bool {
	if l.peek() != '"' {
		return false
	}
	l.emit(tokQuoteStart, l.pos, l.pos+1)
	l.pos++
	l.inQuote = true
	return true
}

func (l *lexer) scanQuotedInner() {
	c := l.peek()

	// Escape sequence
	if c == '\\' && l.peekAt(1) == '"' {
		l.emit(tokOther, l.pos, l.pos+2)
		l.pos += 2
		return
	}

	// Closing quote
	if c == '"' {
		l.emit(tokQuoteEnd, l.pos, l.pos+1)
		l.pos++
		l.inQuote = false
		l.bol = false
		return
	}

	// Unclosed quote at newline
	if c == '\n' || c == '\r' {
		l.emitError("unterminated quoted string")
		l.inQuote = false
		return
	}

	// NUL byte inside quote
	if c == 0 {
		l.emitError("line contains NUL byte")
		l.pos++
		l.inQuote = false
		return
	}

	// Whitespace inside quote
	if l.scanWhitespace() {
		return
	}

	// Identifier inside quote
	if l.scanIdent() {
		return
	}

	// Other character
	l.emit(tokOther, l.pos, l.pos+1)
	l.pos++
}

func (l *lexer) matchDirective() (tokenType, uint32) {
	for _, d := range knownDirectives {
		end := l.pos + d.len
		if end <= l.length && l.input[l.pos:end] == d.name {
			if end >= l.length {
				return d.tokType, d.len
			}
			next := l.input[end]
			if next == ' ' || next == '\t' || next == '\n' || next == '\r' {
				return d.tokType, d.len
			}
		}
	}
	return 0, 0
}

type preprocessor struct {
	lex         *lexer
	input       string
	macros      map[string][]token
	currentLine []token
	expandBuf   [2][]token   // reusable buffers for macro expansion
	segBuf      bytes.Buffer // reusable buffer for pipe segment data
	onLine      func(preprocessedLine)
	onWarning   func(preprocessWarning)
	cur         token
	hasCur      bool
	done        bool
}

type preprocessedLine struct {
	segments [][]byte
	line     int
	raw      string
}

type preprocessWarning struct {
	message string
	line    int
	context string
}

func preprocess(content string, onLine func(preprocessedLine), onWarning func(preprocessWarning)) {
	p := &preprocessor{
		lex:       newLexer(content),
		input:     content,
		macros:    make(map[string][]token),
		onLine:    onLine,
		onWarning: onWarning,
	}
	p.run()
}

func (p *preprocessor) run() {
	for !p.done {
		p.processToken()
	}
}

func (p *preprocessor) peek() token {
	if p.hasCur {
		return p.cur
	}
	if p.done {
		return token{}
	}
	tok, ok := p.lex.next()
	if !ok {
		p.done = true
		return token{}
	}
	p.cur = tok
	p.hasCur = true
	return p.cur
}

func (p *preprocessor) advance() token {
	tok := p.peek()
	p.hasCur = false
	return tok
}

func (p *preprocessor) skipWhitespace() {
	for !p.done && p.peek().typ == tokWhitespace {
		p.advance()
	}
}

func (p *preprocessor) skipToNewline() {
	for !p.done && p.peek().typ != tokNewline {
		p.advance()
	}
}

func (p *preprocessor) warn(message string, line int, context string) {
	p.onWarning(preprocessWarning{
		message: message,
		line:    line,
		context: context,
	})
}

func (p *preprocessor) processToken() {
	tok := p.peek()
	if p.done {
		return
	}

	switch tok.typ {
	case tokError:
		p.warn(p.lex.errorMsg(tok), int(tok.line), p.joinTokens(p.currentLine))
		p.currentLine = p.currentLine[:0]
		p.advance()
		p.skipToNewline()
	case tokComment:
		p.advance()
	case tokNewline:
		p.handleNewline()
	case tokDefine:
		p.handleDefine()
	case tokLineContinuation:
		p.advance()
		p.skipWhitespace()
	default:
		p.currentLine = append(p.currentLine, p.advance())
	}
}

func (p *preprocessor) handleNewline() {
	newlineTok := p.advance()

	if len(p.currentLine) > 0 {
		expanded, ok := p.expandMacros(p.currentLine)
		if !ok {
			p.warn("macro expansion limit reached", int(newlineTok.line), p.joinTokens(p.currentLine))
		} else if p.trimmedLen(expanded) > maxLineLength {
			p.warn("expanded line exceeds maximum length", int(newlineTok.line), p.joinTokens(p.currentLine))
		} else if segments := p.splitByPipe(expanded); len(segments) > 0 {
			p.onLine(preprocessedLine{
				segments: segments,
				line:     int(newlineTok.line),
				raw:      p.joinTokens(p.currentLine),
			})
		}
	}
	p.currentLine = p.currentLine[:0]
}

func (p *preprocessor) trimmedLen(tokens []token) int {
	start := 0
	for start < len(tokens) && tokens[start].typ == tokWhitespace {
		start++
	}
	end := len(tokens)
	for end > start && tokens[end-1].typ == tokWhitespace {
		end--
	}
	n := 0
	for _, tok := range tokens[start:end] {
		n += int(tok.end - tok.start)
	}
	return n
}

func (p *preprocessor) handleDefine() {
	defineTok := p.advance() // skip #define
	p.skipWhitespace()

	if p.peek().typ != tokIdent {
		p.warn("expected identifier after #define", int(defineTok.line), "")
		p.skipToNewline()
		return
	}

	name := p.advance().val(p.input)
	p.skipWhitespace()

	// Collect value tokens until newline, skipping comments
	var valueTokens []token
	for !p.done && p.peek().typ != tokNewline {
		tok := p.advance()
		if tok.typ == tokError {
			p.warn(p.lex.errorMsg(tok), int(tok.line), name)
			p.skipToNewline()
			return
		}
		if tok.typ != tokComment {
			valueTokens = append(valueTokens, tok)
		}
	}

	// Trim trailing whitespace left after stripping inline comments
	for len(valueTokens) > 0 && valueTokens[len(valueTokens)-1].typ == tokWhitespace {
		valueTokens = valueTokens[:len(valueTokens)-1]
	}

	if _, exists := p.macros[name]; exists {
		p.warn("macro redefined", int(defineTok.line), name)
	}
	p.macros[name] = valueTokens
}

func (p *preprocessor) expandMacros(tokens []token) ([]token, bool) {
	if len(p.macros) == 0 {
		return tokens, true
	}

	src := tokens
	for depth := 0; depth <= maxMacroExpansionDepth; depth++ {
		dst := p.expandBuf[depth%2][:0] // alternate buffers so src and dst never overlap
		changed := false

		for _, tok := range src {
			if tok.typ == tokIdent {
				if expansion, ok := p.macros[tok.val(p.input)]; ok {
					dst = append(dst, expansion...)
					changed = true
					if len(dst) > maxMacroExpansionTokens {
						return nil, false
					}
					continue
				}
			}
			dst = append(dst, tok)
		}

		p.expandBuf[depth%2] = dst // retain grown capacity for next call
		if !changed {
			result := make([]token, len(dst))
			copy(result, dst)
			return result, true
		}
		src = dst
	}

	return nil, false
}

func (p *preprocessor) splitByPipe(tokens []token) [][]byte {
	p.segBuf.Reset()
	var segments [][]byte
	segStart := 0

	for _, tok := range tokens {
		if tok.typ == tokPipe {
			if seg := bytes.TrimSpace(p.segBuf.Bytes()[segStart:p.segBuf.Len()]); len(seg) > 0 {
				segments = append(segments, bytes.Clone(seg))
			}
			segStart = p.segBuf.Len()
		} else {
			p.segBuf.WriteString(p.input[tok.start:tok.end])
		}
	}

	if seg := bytes.TrimSpace(p.segBuf.Bytes()[segStart:p.segBuf.Len()]); len(seg) > 0 {
		segments = append(segments, bytes.Clone(seg))
	}

	return segments
}

func (p *preprocessor) joinTokens(tokens []token) string {
	if len(tokens) == 0 {
		return ""
	}
	var sb strings.Builder
	size := 0
	for _, tok := range tokens {
		size += int(tok.end - tok.start)
	}
	sb.Grow(size)
	for _, tok := range tokens {
		sb.WriteString(p.input[tok.start:tok.end])
	}
	return strings.TrimSpace(sb.String())
}
