package server

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	maxMacroExpansionDepth = 10
	maxPermitConnectLength = 1024
	maxPermitOpenLength    = 512
	maxPermitListenLength  = 512
	maxInputSize           = 1024 * 1024 // 1MB
	maxLineLength          = 64 * 1024   // 64KB
)

type AuthorizedKeyOptions struct {
	PermitConnects   []PermitConnect `json:"permit_connects"`
	PermitOpens      []PermitOpen    `json:"permit_opens"`
	PermitListens    []PermitListen  `json:"permit_listens"`
	Command          string          `json:"command"`
	NoPortForwarding bool            `json:"no_port_forwarding"`
	NoPty            bool            `json:"no_pty"`
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

	if len(content) > maxInputSize {
		return nil, fmt.Errorf("authorized_keys file exceeds maximum size of %d bytes", maxInputSize)
	}

	authKeysDB := make(map[string][]*AuthorizedKeyOptions)

	result := preprocess(string(content))
	for _, warning := range result.warnings {
		slog.Warn("preprocessing warning", "message", warning)
	}

lineLoop:
	for _, line := range result.lines {
		var keys []string
		var keyOpts *AuthorizedKeyOptions

		for _, seg := range line.segments {
			publicKey, _, segOpts, _, err := ssh.ParseAuthorizedKey([]byte(seg))
			if err != nil {
				slog.Warn("skipping line, invalid segment", "line", line.raw, "segment", seg, "error", err)
				continue lineLoop
			}
			if keyOpts == nil {
				if len(segOpts) == 0 {
					slog.Warn("skipping line, first segment must define options", "line", line.raw)
					continue lineLoop
				}
				keyOpts, err = parseAuthorizedKeyOptions(segOpts)
				if err != nil {
					slog.Warn("skipping line, invalid options", "line", line.raw, "error", err)
					continue lineLoop
				}
			} else if len(segOpts) > 0 {
				slog.Warn("skipping line, only first segment can define options", "line", line.raw, "segment", seg)
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

func parseAuthorizedKeyOptions(opts []string) (*AuthorizedKeyOptions, error) {
	authKeyOpts := &AuthorizedKeyOptions{}

	for _, opt := range opts {
		if after, ok := strings.CutPrefix(opt, "permitconnect=\""); ok {
			for val := range strings.SplitSeq(strings.TrimSuffix(after, "\""), ",") {
				permitconnect, err := parsePermitConnect(strings.TrimSpace(val))
				if err != nil {
					return nil, err
				}
				authKeyOpts.PermitConnects = append(authKeyOpts.PermitConnects, *permitconnect)
			}
		} else if after, ok := strings.CutPrefix(opt, "permitopen=\""); ok {
			for val := range strings.SplitSeq(strings.TrimSuffix(after, "\""), ",") {
				permitopen, err := parsePermitOpen(strings.TrimSpace(val))
				if err != nil {
					return nil, err
				}
				authKeyOpts.PermitOpens = append(authKeyOpts.PermitOpens, *permitopen)
			}
		} else if after, ok := strings.CutPrefix(opt, "permitlisten=\""); ok {
			for val := range strings.SplitSeq(strings.TrimSuffix(after, "\""), ",") {
				permitlisten, err := parsePermitListen(strings.TrimSpace(val))
				if err != nil {
					return nil, err
				}
				authKeyOpts.PermitListens = append(authKeyOpts.PermitListens, *permitlisten)
			}
		} else if after, ok := strings.CutPrefix(opt, "command=\""); ok {
			authKeyOpts.Command = strings.ReplaceAll(strings.TrimSuffix(after, "\""), `\"`, `"`)
		} else if opt == "no-port-forwarding" {
			authKeyOpts.NoPortForwarding = true
		} else if opt == "no-pty" {
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

type tokenType int

const (
	tokWhitespace tokenType = iota
	tokNewline
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
	bol    bool
	tokens []token
}

func tokenize(input string) []token {
	l := &lexer{input: input, bol: true}
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
	l.tokens = append(l.tokens, token{typ: typ, value: value})
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
			l.emit(tokWhitespace, " ")
			l.bol = true
			return
		}
		if l.peekAt(1) == '\r' && l.peekAt(2) == '\n' {
			l.pos += 3
			l.emit(tokWhitespace, " ")
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

type preprocessResult struct {
	lines    []preprocessedLine
	warnings []string
}

type preprocessedLine struct {
	segments []string
	raw      string
}

type preprocessor struct {
	tokens      []token
	pos         int
	macros      map[string][]token
	currentLine []token
	result      preprocessResult
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

func (p *preprocessor) warn(msg string) {
	p.result.warnings = append(p.result.warnings, msg)
}

func (p *preprocessor) processToken() {
	tok := p.peek()

	switch tok.typ {
	case tokComment:
		p.advance()
	case tokNewline:
		p.handleNewline()
	case tokDefine:
		p.handleDefine()
	default:
		p.currentLine = append(p.currentLine, p.advance())
	}
}

func (p *preprocessor) handleNewline() {
	p.advance()

	if raw := p.joinTokens(p.currentLine); raw != "" {
		expanded, ok := p.expandMacros(p.currentLine)
		if !ok {
			p.warn("macro expansion limit reached: " + raw)
		} else if len(p.joinTokens(expanded)) > maxLineLength {
			p.warn("expanded line exceeds maximum length: " + raw)
		} else if segments := p.splitByPipe(expanded); len(segments) > 0 {
			p.result.lines = append(p.result.lines, preprocessedLine{
				segments: segments,
				raw:      raw,
			})
		}
	}
	p.currentLine = nil
}

func (p *preprocessor) handleDefine() {
	p.advance() // skip #define
	p.skipWhitespace()

	if p.peek().typ != tokIdent {
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
		p.warn("macro redefined: " + name)
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
