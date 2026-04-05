package authkeys

import (
	"fmt"
	"math"
	"net"
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

	if MatchNamePattern(strings.ToLower(pattern), strings.ToLower(host)) {
		return true
	}

	_, cidr, err := net.ParseCIDR(pattern)
	if err != nil {
		return false
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	return cidr.Contains(ip)
}

func MatchPortPattern(pattern string, port any) bool {
	targetPort, err := strconv.ParseUint(fmt.Sprintf("%v", port), 10, 16)
	if err != nil || targetPort > math.MaxUint16 {
		return false
	}

	if pattern == "*" {
		return true
	}

	if strings.Contains(pattern, "-") {
		parts := strings.Split(pattern, "-")
		if len(parts) == 2 {
			startPort, startErr := strconv.ParseUint(parts[0], 10, 16)
			endPort, endErr := strconv.ParseUint(parts[1], 10, 16)
			if startErr == nil && endErr == nil && startPort <= endPort {
				if targetPort >= startPort && targetPort <= endPort {
					return true
				}
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
