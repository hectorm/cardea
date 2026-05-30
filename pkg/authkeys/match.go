package authkeys

import (
	"fmt"
	"math"
	"net/netip"
	"path"
	"strconv"
	"strings"
)

func MatchPermitConnect(pattern, target PermitConnect) bool {
	return MatchUserPattern(pattern.User, target.User) &&
		MatchHostPattern(pattern.Host, target.Host) &&
		MatchPortPattern(pattern.Port, target.Port)
}

func MatchUserPattern(pattern, user string) bool {
	if user == "" || len(user) > 255 {
		return false
	}

	return MatchNamePattern(pattern, user)
}

func MatchHostPattern(pattern, host string) bool {
	if len(host) > 255 {
		return false
	}

	if strings.Contains(pattern, "/") {
		prefix, err := netip.ParsePrefix(pattern)
		if err != nil {
			return false
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return false
		}
		return prefix.Contains(addr)
	}

	return MatchNamePattern(strings.ToLower(pattern), strings.ToLower(host))
}

func MatchPortPattern(pattern string, port any) bool {
	var targetPort uint64
	switch p := port.(type) {
	case uint16:
		targetPort = uint64(p)
	case uint32:
		targetPort = uint64(p)
	case uint64:
		targetPort = p
	case int:
		if p < 0 {
			return false
		}
		targetPort = uint64(p)
	case string:
		v, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return false
		}
		targetPort = v
	default:
		v, err := strconv.ParseUint(fmt.Sprintf("%v", port), 10, 16)
		if err != nil {
			return false
		}
		targetPort = v
	}
	if targetPort > math.MaxUint16 {
		return false
	}

	if pattern == "*" {
		return true
	}

	if startStr, endStr, isRange := strings.Cut(pattern, "-"); isRange {
		startPort, startErr := strconv.ParseUint(startStr, 10, 16)
		endPort, endErr := strconv.ParseUint(endStr, 10, 16)
		if startErr == nil && endErr == nil && startPort <= endPort {
			if targetPort >= startPort && targetPort <= endPort {
				return true
			}
		}
	} else {
		patternPort, err := strconv.ParseUint(pattern, 10, 16)
		if err == nil && targetPort == patternPort {
			return true
		}
	}

	return false
}

func MatchNamePattern(pattern, value string) bool {
	if strings.Contains(value, "/") || value == "." || value == ".." {
		return false
	}

	match, err := path.Match(pattern, value)
	return err == nil && match
}

func MatchPathPattern(pattern, value string) bool {
	if value == "" {
		return false
	}

	if pattern == "*" {
		return true
	}

	pattern, value = path.Clean(pattern), path.Clean(value)
	if path.IsAbs(pattern) != path.IsAbs(value) {
		return false
	}

	match, err := path.Match(pattern, value)
	return err == nil && match
}
