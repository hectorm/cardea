package authkeys

import (
	"fmt"
	"net"
	"path"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hectorm/cardea/pkg/timewindow"
)

const (
	MaxInputSize           = 256 * 1024 * 1024 // 256MB
	MaxPermitConnectLength = 1024
	MaxPermitTCPLength     = 512
	MaxPermitSocketLength  = 512
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

type Warning struct {
	Message string
	Line    int
	Context string
}

func ParseFile(content []byte) (map[string][]*AuthorizedKeyOptions, []Warning, error) {
	if len(content) > MaxInputSize {
		return nil, nil, fmt.Errorf("authorized_keys content exceeds maximum size of %d bytes", MaxInputSize)
	}

	authKeysDB := make(map[string][]*AuthorizedKeyOptions)
	var warnings []Warning

	preprocess(string(content), func(line preprocessedLine) {
		keyOpts, publicKey, err := ParseLine(line.segments[0])
		if err != nil {
			warnings = append(warnings, Warning{Message: err.Error(), Line: line.line, Context: line.raw})
			return
		}
		keys := []string{string(publicKey.Marshal())}

		for _, seg := range line.segments[1:] {
			publicKey, _, opts, err := ParseKey(seg)
			if err != nil {
				warnings = append(warnings, Warning{Message: err.Error(), Line: line.line, Context: line.raw})
				return
			}
			if len(opts) > 0 {
				warnings = append(warnings, Warning{Message: "unexpected options", Line: line.line, Context: line.raw})
				return
			}
			keys = append(keys, string(publicKey.Marshal()))
		}

		for _, key := range keys {
			authKeysDB[key] = append(authKeysDB[key], keyOpts)
		}
	}, func(w Warning) {
		warnings = append(warnings, w)
	})

	return authKeysDB, warnings, nil
}

func ParseLine(line []byte) (*AuthorizedKeyOptions, ssh.PublicKey, error) {
	publicKey, comment, opts, err := ParseKey(line)
	if err != nil {
		return nil, nil, err
	}
	if len(opts) == 0 {
		return nil, nil, fmt.Errorf("missing options")
	}
	authKeyOpts, err := ParseOptions(opts)
	if err != nil {
		return nil, nil, err
	}
	authKeyOpts.Comment = comment
	return authKeyOpts, publicKey, nil
}

func ParseKey(line []byte) (ssh.PublicKey, string, []string, error) {
	publicKey, comment, opts, _, err := ssh.ParseAuthorizedKey(line)
	if err != nil {
		return nil, "", nil, err
	}
	return publicKey, comment, opts, nil
}

func ParseOptions(opts []string) (*AuthorizedKeyOptions, error) {
	authKeyOpts := &AuthorizedKeyOptions{}

	for _, opt := range opts {
		name, val, ok := SplitOption(opt)
		if !ok {
			return nil, fmt.Errorf("malformed option: %s", opt)
		}

		switch name {
		case "permitconnect":
			for v := range strings.SplitSeq(val, ",") {
				permitconnect, err := ParsePermitConnect(strings.TrimSpace(v))
				if err != nil {
					return nil, fmt.Errorf("invalid permitconnect: %w", err)
				}
				authKeyOpts.PermitConnects = append(authKeyOpts.PermitConnects, *permitconnect)
			}
		case "permitopen":
			for v := range strings.SplitSeq(val, ",") {
				permitopen, err := ParsePermitTCP(strings.TrimSpace(v))
				if err != nil {
					return nil, fmt.Errorf("invalid permitopen: %w", err)
				}
				authKeyOpts.PermitOpens = append(authKeyOpts.PermitOpens, *permitopen)
			}
		case "permitlisten":
			for v := range strings.SplitSeq(val, ",") {
				permitlisten, err := ParsePermitTCP(strings.TrimSpace(v))
				if err != nil {
					return nil, fmt.Errorf("invalid permitlisten: %w", err)
				}
				authKeyOpts.PermitListens = append(authKeyOpts.PermitListens, *permitlisten)
			}
		case "permitsocketopen":
			permitsocketopen, err := ParsePermitSocket(strings.TrimSpace(val))
			if err != nil {
				return nil, fmt.Errorf("invalid permitsocketopen: %w", err)
			}
			authKeyOpts.PermitSocketOpens = append(authKeyOpts.PermitSocketOpens, *permitsocketopen)
		case "permitsocketlisten":
			permitsocketlisten, err := ParsePermitSocket(strings.TrimSpace(val))
			if err != nil {
				return nil, fmt.Errorf("invalid permitsocketlisten: %w", err)
			}
			authKeyOpts.PermitSocketListens = append(authKeyOpts.PermitSocketListens, *permitsocketlisten)
		case "environment":
			environment, err := ParseEnvironment(val)
			if err != nil {
				return nil, fmt.Errorf("invalid environment: %w", err)
			}
			authKeyOpts.Environments = append(authKeyOpts.Environments, *environment)
		case "from":
			for v := range strings.SplitSeq(val, ",") {
				from, err := ParseFrom(strings.TrimSpace(v))
				if err != nil {
					return nil, fmt.Errorf("invalid from: %w", err)
				}
				authKeyOpts.Froms = append(authKeyOpts.Froms, from)
			}
		case "start-time":
			t, err := ParseTimespec(val)
			if err != nil {
				return nil, fmt.Errorf("invalid start-time: %w", err)
			}
			if authKeyOpts.StartTime == nil || t.After(*authKeyOpts.StartTime) {
				authKeyOpts.StartTime = &t
			}
		case "expiry-time":
			t, err := ParseTimespec(val)
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

func SplitOption(s string) (name, value string, ok bool) {
	name, quoted, hasValue := strings.Cut(s, "=")
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

func QuoteOptionValue(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for i := range len(s) {
		if s[i] == '"' {
			b.WriteString(`\"`)
		} else {
			b.WriteByte(s[i])
		}
	}
	b.WriteByte('"')
	return b.String()
}

func ParsePermitConnect(s string) (*PermitConnect, error) {
	if s != "" && len(s) <= MaxPermitConnectLength {
		// Try format <user>@<host>[:<port>]
		if i := strings.LastIndex(s, "@"); i != -1 {
			user, addr := s[:i], s[i+1:]
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
		if parts := strings.Split(s, "+"); len(parts) == 3 {
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

	return nil, fmt.Errorf("expected <user>@<host>[:<port>] or <user>+<host>[+<port>], got %s", s)
}

func ParsePermitTCP(s string) (*PermitTCP, error) {
	if s == "" {
		return nil, fmt.Errorf("empty value")
	}
	if len(s) > MaxPermitTCPLength {
		return nil, fmt.Errorf("exceeds maximum length of %d", MaxPermitTCPLength)
	}

	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" || port == "" {
		return nil, fmt.Errorf("expected <host>:<port>, got %s", s)
	}

	return &PermitTCP{Host: host, Port: port}, nil
}

func ParsePermitSocket(s string) (*PermitSocket, error) {
	if s == "" {
		return nil, fmt.Errorf("empty value")
	}
	if len(s) > MaxPermitSocketLength {
		return nil, fmt.Errorf("exceeds maximum length of %d", MaxPermitSocketLength)
	}

	if s == "*" {
		return &PermitSocket{Path: s}, nil
	}

	s = path.Clean(s)
	return &PermitSocket{Path: s}, nil
}

func ParseEnvironment(s string) (*Environment, error) {
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

func ParseFrom(s string) (string, error) {
	if s == "" {
		return "", fmt.Errorf("empty value")
	}

	return s, nil
}

func ParseTimespec(s string) (time.Time, error) {
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
