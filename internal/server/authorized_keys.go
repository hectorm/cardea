package server

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hectorm/cardea/internal/timewindow"
)

const (
	maxInputSize            = 1024 * 1024 // 1MB
	maxLineLength           = 64 * 1024   // 64KB
	maxPermitConnectLength  = 1024
	maxPermitOpenLength     = 512
	maxPermitListenLength   = 512
	maxMacroExpansionDepth  = 10
	maxMacroExpansionTokens = 16 * 1024
)

type AuthorizedKeyOptions struct {
	PermitConnects   []PermitConnect        `json:"permit_connects"`
	PermitOpens      []PermitOpen           `json:"permit_opens"`
	PermitListens    []PermitListen         `json:"permit_listens"`
	Froms            []string               `json:"froms"`
	StartTime        *time.Time             `json:"start_time"`
	ExpiryTime       *time.Time             `json:"expiry_time"`
	TimeWindow       *timewindow.TimeWindow `json:"time_window"`
	Command          string                 `json:"command"`
	NoPortForwarding bool                   `json:"no_port_forwarding"`
	NoPty            bool                   `json:"no_pty"`
}

type PermitConnect struct {
	User string `json:"user"`
	Host string `json:"host"`
	Port string `json:"port"`
}

type PermitOpen struct {
	Host string `json:"host"`
	Port string `json:"port"`
}

type PermitListen struct {
	Host string `json:"host"`
	Port string `json:"port"`
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

	result := preprocess(string(content))
	for _, warning := range result.warnings {
		if warning.context != "" {
			slog.Warn("authorized_keys file parse", "line", warning.line, "reason", warning.message, "context", warning.context)
		} else {
			slog.Warn("authorized_keys file parse", "line", warning.line, "reason", warning.message)
		}
	}

lineLoop:
	for _, line := range result.lines {
		var keys []string
		var keyOpts *AuthorizedKeyOptions

		for _, seg := range line.segments {
			publicKey, _, segOpts, _, err := ssh.ParseAuthorizedKey([]byte(seg))
			if err != nil {
				slog.Warn("authorized_keys file parse", "line", line.line, "reason", err, "context", line.raw)
				continue lineLoop
			}
			if keyOpts == nil {
				if len(segOpts) == 0 {
					slog.Warn("authorized_keys file parse", "line", line.line, "reason", "missing options", "context", line.raw)
					continue lineLoop
				}
				keyOpts, err = parseOptions(segOpts)
				if err != nil {
					slog.Warn("authorized_keys file parse", "line", line.line, "reason", err, "context", line.raw)
					continue lineLoop
				}
			} else if len(segOpts) > 0 {
				slog.Warn("authorized_keys file parse", "line", line.line, "reason", "unexpected options", "context", line.raw)
				continue lineLoop
			}
			keys = append(keys, string(publicKey.Marshal()))
		}

		for _, key := range keys {
			authKeysDB[key] = append(authKeysDB[key], keyOpts)
		}
	}

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
					return nil, err
				}
				authKeyOpts.PermitConnects = append(authKeyOpts.PermitConnects, *permitconnect)
			}
		case "permitopen":
			for v := range strings.SplitSeq(val, ",") {
				permitopen, err := parsePermitOpen(strings.TrimSpace(v))
				if err != nil {
					return nil, err
				}
				authKeyOpts.PermitOpens = append(authKeyOpts.PermitOpens, *permitopen)
			}
		case "permitlisten":
			for v := range strings.SplitSeq(val, ",") {
				permitlisten, err := parsePermitListen(strings.TrimSpace(v))
				if err != nil {
					return nil, err
				}
				authKeyOpts.PermitListens = append(authKeyOpts.PermitListens, *permitlisten)
			}
		case "from":
			for v := range strings.SplitSeq(val, ",") {
				authKeyOpts.Froms = append(authKeyOpts.Froms, strings.TrimSpace(v))
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
		case "pty":
			authKeyOpts.NoPty = false
		case "no-pty":
			authKeyOpts.NoPty = true
		case "restrict":
			authKeyOpts.NoPortForwarding = true
			authKeyOpts.NoPty = true
		}
	}

	if len(authKeyOpts.PermitConnects) == 0 {
		return nil, fmt.Errorf("missing required 'permitconnect' option")
	}

	if len(authKeyOpts.PermitOpens) == 0 {
		authKeyOpts.PermitOpens = []PermitOpen{
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

	return nil, fmt.Errorf("invalid permitconnect format, expected <user>@<host>[:<port>] or <user>+<host>[+<port>], got %s", permitconnect)
}

func parsePermitOpen(permitopen string) (*PermitOpen, error) {
	if permitopen != "" && len(permitopen) <= maxPermitOpenLength {
		host, port, err := net.SplitHostPort(permitopen)
		if err == nil && host != "" && port != "" {
			return &PermitOpen{Host: host, Port: port}, nil
		}
	}

	return nil, fmt.Errorf("invalid permitopen format, expected <host>:<port>, got %s", permitopen)
}

func parsePermitListen(permitlisten string) (*PermitListen, error) {
	if permitlisten != "" && len(permitlisten) <= maxPermitListenLength {
		host, port, err := net.SplitHostPort(permitlisten)
		if err == nil && host != "" && port != "" {
			return &PermitListen{Host: host, Port: port}, nil
		}
	}

	return nil, fmt.Errorf("invalid permitlisten format, expected <host>:<port>, got %s", permitlisten)
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

type tokenType int

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
	typ   tokenType
	value string
	line  int
}

var knownDirectives = []struct {
	name    string
	tokType tokenType
}{
	{"#define", tokDefine},
}

type lexer struct {
	input  string
	pos    int
	line   int
	bol    bool
	tokens []token
}

func tokenize(input string) []token {
	l := &lexer{input: input, line: 1, bol: true}
	l.run()
	// Ensure token stream ends with a newline for uniform processing
	if len(l.tokens) == 0 || l.tokens[len(l.tokens)-1].typ != tokNewline {
		l.tokens = append(l.tokens, token{typ: tokNewline, value: "\n", line: l.line})
	}
	return l.tokens
}

func (l *lexer) run() {
	for l.pos < len(l.input) {
		l.scanToken()
	}
}

func (l *lexer) emit(typ tokenType, value string) {
	l.tokens = append(l.tokens, token{typ: typ, value: value, line: l.line})
}

func (l *lexer) peek() byte {
	if l.pos >= len(l.input) {
		return 0
	}
	return l.input[l.pos]
}

func (l *lexer) peekAt(offset int) byte {
	if l.pos+offset >= len(l.input) {
		return 0
	}
	return l.input[l.pos+offset]
}

func (l *lexer) scanToken() {
	c := l.peek()

	// Line continuation: backslash followed by newline
	if c == '\\' {
		if l.peekAt(1) == '\n' {
			l.pos += 2
			l.emit(tokLineContinuation, "")
			l.line++
			l.bol = true
			return
		}
		if l.peekAt(1) == '\r' && l.peekAt(2) == '\n' {
			l.pos += 3
			l.emit(tokLineContinuation, "")
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
		l.emit(tokNewline, l.input[start:l.pos])
		l.line++
		l.bol = true
		return
	}

	// Directive or comment
	if c == '#' {
		if l.bol {
			// Directives only at beginning of line
			if typ, length := l.matchDirective(); length > 0 {
				l.emit(typ, l.input[l.pos:l.pos+length])
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
		l.emit(tokPipe, "|")
		l.pos++
		l.bol = false
		return
	}

	// Other character
	l.emit(tokOther, string(c))
	l.pos++
	l.bol = false
}

func (l *lexer) scanBOLComment() {
	start := l.pos
	l.pos++ // skip #
	for l.pos < len(l.input) && l.peek() != '\n' && l.peek() != '\r' {
		l.pos++
	}
	// Include trailing newline in comment
	if l.peek() == '\r' {
		l.pos++
	}
	if l.peek() == '\n' {
		l.pos++
	}
	l.emit(tokComment, l.input[start:l.pos])
	l.line++
	l.bol = true
}

func (l *lexer) scanInlineComment() {
	start := l.pos
	l.pos++ // skip #
	for l.pos < len(l.input) && l.peek() != '\n' && l.peek() != '\r' {
		l.pos++
	}
	// Do not include trailing newline, it will be a separate tokNewline
	l.emit(tokComment, l.input[start:l.pos])
	l.bol = false
}

func (l *lexer) scanWhitespace() bool {
	if l.peek() != ' ' && l.peek() != '\t' {
		return false
	}
	start := l.pos
	for l.pos < len(l.input) && (l.peek() == ' ' || l.peek() == '\t') {
		l.pos++
	}
	l.emit(tokWhitespace, l.input[start:l.pos])
	return true
}

func (l *lexer) scanIdent() bool {
	c := l.peek()
	if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '_') {
		return false
	}
	start := l.pos
	l.pos++
	for l.pos < len(l.input) {
		c = l.peek()
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '_' || c >= '0' && c <= '9') {
			break
		}
		l.pos++
	}
	l.emit(tokIdent, l.input[start:l.pos])
	return true
}

func (l *lexer) scanQuoted() bool {
	if l.peek() != '"' {
		return false
	}
	l.emit(tokQuoteStart, "\"")
	l.pos++

	for l.pos < len(l.input) {
		c := l.peek()

		// Escape sequence
		if c == '\\' && l.peekAt(1) != 0 && l.peekAt(1) != '\n' && l.peekAt(1) != '\r' {
			l.emit(tokOther, l.input[l.pos:l.pos+2])
			l.pos += 2
			continue
		}

		// Closing quote
		if c == '"' {
			l.emit(tokQuoteEnd, "\"")
			l.pos++
			return true
		}

		// Unclosed quote at newline
		if c == '\n' || c == '\r' {
			l.emit(tokError, "unterminated quoted string")
			return true
		}

		// Whitespace inside quote
		if l.scanWhitespace() {
			continue
		}

		// Identifier inside quote
		if l.scanIdent() {
			continue
		}

		// Other character
		l.emit(tokOther, string(c))
		l.pos++
	}

	// Reached EOF without closing quote
	l.emit(tokError, "unterminated quoted string")

	return true
}

func (l *lexer) matchDirective() (tokenType, int) {
	for _, d := range knownDirectives {
		end := l.pos + len(d.name)
		if end <= len(l.input) && l.input[l.pos:end] == d.name {
			if end >= len(l.input) {
				return d.tokType, len(d.name)
			}
			next := l.input[end]
			if next == ' ' || next == '\t' || next == '\n' || next == '\r' {
				return d.tokType, len(d.name)
			}
		}
	}
	return 0, 0
}

type preprocessor struct {
	tokens      []token
	pos         int
	macros      map[string][]token
	currentLine []token
	result      preprocessResult
}

type preprocessResult struct {
	lines    []preprocessedLine
	warnings []preprocessWarning
}

type preprocessedLine struct {
	segments []string
	line     int
	raw      string
}

type preprocessWarning struct {
	message string
	line    int
	context string
}

func preprocess(content string) preprocessResult {
	p := &preprocessor{
		tokens: tokenize(content),
		macros: make(map[string][]token),
	}
	p.run()
	return p.result
}

func (p *preprocessor) run() {
	for p.pos < len(p.tokens) {
		p.processToken()
	}
}

func (p *preprocessor) peek() token {
	if p.pos >= len(p.tokens) {
		return token{}
	}
	return p.tokens[p.pos]
}

func (p *preprocessor) advance() token {
	tok := p.peek()
	p.pos++
	return tok
}

func (p *preprocessor) skipWhitespace() {
	for p.pos < len(p.tokens) && p.peek().typ == tokWhitespace {
		p.pos++
	}
}

func (p *preprocessor) skipToNewline() {
	for p.pos < len(p.tokens) && p.peek().typ != tokNewline {
		p.pos++
	}
}

func (p *preprocessor) warn(message string, line int, context string) {
	p.result.warnings = append(p.result.warnings, preprocessWarning{
		message: message,
		line:    line,
		context: context,
	})
}

func (p *preprocessor) processToken() {
	tok := p.peek()

	switch tok.typ {
	case tokError:
		p.warn(tok.value, tok.line, "")
		p.advance()
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

	if raw := p.joinTokens(p.currentLine); raw != "" {
		expanded, ok := p.expandMacros(p.currentLine)
		if !ok {
			p.warn("macro expansion limit reached", newlineTok.line, raw)
		} else if len(p.joinTokens(expanded)) > maxLineLength {
			p.warn("expanded line exceeds maximum length", newlineTok.line, raw)
		} else if segments := p.splitByPipe(expanded); len(segments) > 0 {
			p.result.lines = append(p.result.lines, preprocessedLine{
				segments: segments,
				line:     newlineTok.line,
				raw:      raw,
			})
		}
	}
	p.currentLine = nil
}

func (p *preprocessor) handleDefine() {
	defineTok := p.advance() // skip #define
	p.skipWhitespace()

	if p.peek().typ != tokIdent {
		p.warn("expected identifier after #define", defineTok.line, "")
		p.skipToNewline()
		return
	}

	name := p.advance().value
	p.skipWhitespace()

	// Collect value tokens until newline, skipping comments
	var valueTokens []token
	for p.pos < len(p.tokens) && p.peek().typ != tokNewline {
		tok := p.advance()
		if tok.typ != tokComment {
			valueTokens = append(valueTokens, tok)
		}
	}

	// Trim trailing whitespace from value (before any inline comment)
	for len(valueTokens) > 0 && valueTokens[len(valueTokens)-1].typ == tokWhitespace {
		valueTokens = valueTokens[:len(valueTokens)-1]
	}

	if _, exists := p.macros[name]; exists {
		p.warn("macro redefined", defineTok.line, name)
	}
	p.macros[name] = valueTokens
}

func (p *preprocessor) expandMacros(tokens []token) ([]token, bool) {
	if len(p.macros) == 0 {
		return tokens, true
	}

	for depth := 0; depth <= maxMacroExpansionDepth; depth++ {
		result := make([]token, 0, len(tokens))
		changed := false

		for _, tok := range tokens {
			if tok.typ == tokIdent {
				if expansion, ok := p.macros[tok.value]; ok {
					result = append(result, expansion...)
					changed = true
					if len(result) > maxMacroExpansionTokens {
						return nil, false
					}
					continue
				}
			}
			result = append(result, tok)
		}

		if !changed {
			return result, true
		}
		tokens = result
	}

	return nil, false
}

func (p *preprocessor) splitByPipe(tokens []token) []string {
	var segments []string
	var current []token

	for _, tok := range tokens {
		if tok.typ == tokPipe {
			if s := p.joinTokens(current); s != "" {
				segments = append(segments, s)
			}
			current = nil
		} else {
			current = append(current, tok)
		}
	}

	if s := p.joinTokens(current); s != "" {
		segments = append(segments, s)
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
		size += len(tok.value)
	}
	sb.Grow(size)
	for _, tok := range tokens {
		sb.WriteString(tok.value)
	}
	return strings.TrimSpace(sb.String())
}
