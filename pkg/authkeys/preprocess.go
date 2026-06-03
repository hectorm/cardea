package authkeys

import (
	"bytes"
	"strings"
)

const (
	MaxLineLength           = 16 * 1024 * 1024 // 16MB
	MaxMacroExpansionDepth  = 10
	MaxMacroExpansionTokens = 256 * 1024
)

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
	tokMacroRef
	tokEscapedMacroRef
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

func (t token) macroName(input string) string {
	return input[t.start+2 : t.end-2]
}

var knownDirectives = []struct {
	name    string
	len     uint32
	tokType tokenType
}{
	{"#define", 7, tokDefine},
}

func isNameStart(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '_'
}

func isNameCont(c byte) bool {
	return isNameStart(c) || c >= '0' && c <= '9'
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

	// Escaped macro reference \{{NAME}}
	if l.scanEscapedMacroRef() {
		l.bol = false
		return
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

	// Macro reference {{NAME}}
	if l.scanMacroRef() {
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
	if !isNameStart(l.peek()) {
		return false
	}
	start := l.pos
	l.pos++
	for isNameCont(l.peek()) {
		l.pos++
	}
	l.emit(tokIdent, start, l.pos)
	return true
}

func (l *lexer) scanMacroRef() bool {
	if l.peek() != '{' || l.peekAt(1) != '{' {
		return false
	}
	off := uint32(2)
	if !isNameStart(l.peekAt(off)) {
		return false
	}
	off++
	for isNameCont(l.peekAt(off)) {
		off++
	}
	if l.peekAt(off) != '}' || l.peekAt(off+1) != '}' {
		return false
	}
	end := l.pos + off + 2
	l.emit(tokMacroRef, l.pos, end)
	l.pos = end
	return true
}

func (l *lexer) scanEscapedMacroRef() bool {
	if l.peek() != '\\' || l.peekAt(1) != '{' || l.peekAt(2) != '{' {
		return false
	}
	off := uint32(3)
	if !isNameStart(l.peekAt(off)) {
		return false
	}
	off++
	for isNameCont(l.peekAt(off)) {
		off++
	}
	if l.peekAt(off) != '}' || l.peekAt(off+1) != '}' {
		return false
	}
	end := l.pos + off + 2
	l.emit(tokEscapedMacroRef, l.pos, end)
	l.pos = end
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

	// Escaped macro reference \{{NAME}} inside quote
	if l.scanEscapedMacroRef() {
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

	// Macro reference {{NAME}} inside quote
	if l.scanMacroRef() {
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
	lex          *lexer
	input        string
	bareMacros   map[string][]token
	bracedMacros map[string][]token
	currentLine  []token
	expandBuf    [2][]token   // reusable buffers for macro expansion
	segBuf       bytes.Buffer // reusable buffer for pipe segment data
	onLine       func(preprocessedLine)
	onWarning    func(Warning)
	cur          token
	hasCur       bool
	done         bool
}

type preprocessedLine struct {
	segments  [][]byte
	line      int
	rawInput  string
	rawTokens []token
}

func (l preprocessedLine) rawContext() string {
	return joinTokenText(l.rawInput, l.rawTokens)
}

func preprocess(content string, onLine func(preprocessedLine), onWarning func(Warning)) {
	p := &preprocessor{
		lex:          newLexer(content),
		input:        content,
		bareMacros:   make(map[string][]token),
		bracedMacros: make(map[string][]token),
		onLine:       onLine,
		onWarning:    onWarning,
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
	p.onWarning(Warning{
		Message: message,
		Line:    line,
		Context: context,
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
		} else if p.trimmedLen(expanded) > MaxLineLength {
			p.warn("expanded line exceeds maximum length", int(newlineTok.line), p.joinTokens(p.currentLine))
		} else if segments := p.splitByPipe(expanded); len(segments) > 0 {
			p.onLine(preprocessedLine{
				segments:  segments,
				line:      int(newlineTok.line),
				rawInput:  p.input,
				rawTokens: p.currentLine,
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
		if tok.typ == tokEscapedMacroRef {
			n += int(tok.end - tok.start - 1)
		} else {
			n += int(tok.end - tok.start)
		}
	}
	return n
}

func (p *preprocessor) handleDefine() {
	defineTok := p.advance() // skip #define
	p.skipWhitespace()

	nameTok := p.peek()
	var name string
	var macros map[string][]token
	switch nameTok.typ {
	case tokMacroRef:
		name, macros = nameTok.macroName(p.input), p.bracedMacros
	case tokIdent:
		name, macros = nameTok.val(p.input), p.bareMacros
	default:
		p.warn("expected identifier after #define", int(defineTok.line), "")
		p.skipToNewline()
		return
	}
	p.advance()
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

	if _, exists := macros[name]; exists {
		p.warn("macro redefined", int(defineTok.line), name)
	}
	macros[name] = valueTokens
}

func (p *preprocessor) lookupMacro(tok token) (expansion []token, ok bool) {
	switch tok.typ {
	case tokIdent:
		expansion, ok = p.bareMacros[tok.val(p.input)]
	case tokMacroRef:
		name := tok.macroName(p.input)
		if expansion, ok = p.bracedMacros[name]; !ok {
			expansion, ok = p.bareMacros[name]
		}
	}
	return expansion, ok
}

func (p *preprocessor) expandMacros(tokens []token) ([]token, bool) {
	if len(p.bareMacros) == 0 && len(p.bracedMacros) == 0 {
		return tokens, true
	}

	src := tokens
	for depth := 0; depth <= MaxMacroExpansionDepth; depth++ {
		dst := p.expandBuf[depth%2][:0] // alternate buffers so src and dst never overlap
		changed := false

		for _, tok := range src {
			if expansion, ok := p.lookupMacro(tok); ok {
				dst = append(dst, expansion...)
				changed = true
				if len(dst) > MaxMacroExpansionTokens {
					return nil, false
				}
				continue
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
		switch tok.typ {
		case tokPipe:
			if seg := bytes.TrimSpace(p.segBuf.Bytes()[segStart:p.segBuf.Len()]); len(seg) > 0 {
				segments = append(segments, bytes.Clone(seg))
			}
			segStart = p.segBuf.Len()
		case tokEscapedMacroRef:
			p.segBuf.WriteString(p.input[tok.start+1 : tok.end])
		default:
			p.segBuf.WriteString(p.input[tok.start:tok.end])
		}
	}

	if seg := bytes.TrimSpace(p.segBuf.Bytes()[segStart:p.segBuf.Len()]); len(seg) > 0 {
		segments = append(segments, bytes.Clone(seg))
	}

	return segments
}

func (p *preprocessor) joinTokens(tokens []token) string {
	return joinTokenText(p.input, tokens)
}

func joinTokenText(input string, tokens []token) string {
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
		sb.WriteString(input[tok.start:tok.end])
	}
	return strings.TrimSpace(sb.String())
}
