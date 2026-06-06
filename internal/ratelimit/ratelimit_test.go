package ratelimit

import (
	"testing"
	"time"
)

func TestRateLimit(t *testing.T) {
	const (
		opTake = iota
		opReset
		opExpire
	)
	type step struct {
		op          int
		ip          string
		takes       int
		wantAllowed int
	}
	tests := []struct {
		name         string
		maxEntries   int
		maxCount     int
		promoteAfter int
		steps        []step
	}{
		{
			name:     "ipv4",
			maxCount: 3,
			steps: []step{
				{op: opTake, ip: "203.0.113.1", takes: 4, wantAllowed: 3},
			},
		},
		{
			name:     "ipv6",
			maxCount: 3,
			steps: []step{
				{op: opTake, ip: "2001:db8:0:0::1", takes: 4, wantAllowed: 3},
			},
		},
		{
			name:         "escalation",
			maxCount:     2,
			promoteAfter: 2,
			steps: []step{
				{op: opTake, ip: "2001:db8:0:0::1", takes: 3, wantAllowed: 2},
				{op: opTake, ip: "2001:db8:0:1::1", takes: 3, wantAllowed: 2},
				{op: opTake, ip: "2001:db8:0:100::1", takes: 3, wantAllowed: 2},
				{op: opTake, ip: "2001:db8:0:101::1", takes: 3, wantAllowed: 2},
				{op: opTake, ip: "2001:db8:0:200::1", takes: 1, wantAllowed: 0},
			},
		},
		{
			name:         "busy_prefix",
			maxCount:     2,
			promoteAfter: 2,
			steps: []step{
				{op: opTake, ip: "2001:db8:0:0::1", takes: 50, wantAllowed: 2},
				{op: opTake, ip: "2001:db8:0:1::1", takes: 1, wantAllowed: 1},
			},
		},
		{
			name:     "reset",
			maxCount: 2,
			steps: []step{
				{op: opTake, ip: "2001:db8:0:0::1", takes: 1, wantAllowed: 1},
				{op: opReset, ip: "2001:db8:0:0::1"},
				{op: opTake, ip: "2001:db8:0:0::1", takes: 2, wantAllowed: 2},
				{op: opReset, ip: "2001:db8:0:1::1"},
			},
		},
		{
			name:         "reset_unwinds_parents",
			maxCount:     2,
			promoteAfter: 2,
			steps: []step{
				{op: opTake, ip: "2001:db8:0:0::1", takes: 3, wantAllowed: 2},
				{op: opTake, ip: "2001:db8:0:1::1", takes: 3, wantAllowed: 2},
				{op: opTake, ip: "2001:db8:0:100::1", takes: 3, wantAllowed: 2},
				{op: opTake, ip: "2001:db8:0:101::1", takes: 3, wantAllowed: 2},
				{op: opTake, ip: "2001:db8:0:200::1", takes: 1, wantAllowed: 0},
				{op: opReset, ip: "2001:db8:0:0::1"},
				{op: opTake, ip: "2001:db8:0:200::1", takes: 1, wantAllowed: 1},
			},
		},
		{
			name:     "expiry",
			maxCount: 2,
			steps: []step{
				{op: opTake, ip: "203.0.113.1", takes: 3, wantAllowed: 2},
				{op: opExpire, ip: "203.0.113.1"},
				{op: opTake, ip: "203.0.113.1", takes: 1, wantAllowed: 1},
			},
		},
		{
			name:     "independent_ipv4",
			maxCount: 2,
			steps: []step{
				{op: opTake, ip: "203.0.113.1", takes: 3, wantAllowed: 2},
				{op: opTake, ip: "203.0.113.2", takes: 3, wantAllowed: 2},
			},
		},
		{
			name:     "ipv4_mapped",
			maxCount: 2,
			steps: []step{
				{op: opTake, ip: "::ffff:203.0.113.1", takes: 1, wantAllowed: 1},
				{op: opTake, ip: "203.0.113.1", takes: 2, wantAllowed: 1},
			},
		},
		{
			name:     "invalid_ip",
			maxCount: 2,
			steps: []step{
				{op: opTake, ip: "not-an-ip", takes: 3, wantAllowed: 2},
			},
		},
		{
			name:       "eviction",
			maxEntries: 2,
			maxCount:   2,
			steps: []step{
				{op: opTake, ip: "203.0.113.1", takes: 2, wantAllowed: 2},
				{op: opTake, ip: "203.0.113.2", takes: 1, wantAllowed: 1},
				{op: opTake, ip: "203.0.113.3", takes: 1, wantAllowed: 1},
				{op: opTake, ip: "203.0.113.1", takes: 1, wantAllowed: 1},
			},
		},
		{
			name:       "eviction_keep_hot",
			maxEntries: 2,
			maxCount:   2,
			steps: []step{
				{op: opTake, ip: "203.0.113.1", takes: 2, wantAllowed: 2},
				{op: opTake, ip: "203.0.113.2", takes: 1, wantAllowed: 1},
				{op: opTake, ip: "203.0.113.1", takes: 1, wantAllowed: 0},
				{op: opTake, ip: "203.0.113.3", takes: 1, wantAllowed: 1},
				{op: opTake, ip: "203.0.113.1", takes: 1, wantAllowed: 0},
				{op: opTake, ip: "203.0.113.2", takes: 1, wantAllowed: 1},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rl := NewRateLimit(tt.maxEntries, tt.maxCount, time.Hour)
			if tt.promoteAfter != 0 {
				rl.promoteAfter = tt.promoteAfter
			}

			for i, s := range tt.steps {
				switch s.op {
				case opReset:
					rl.Reset(s.ip)
				case opExpire:
					rl.mu.Lock()
					rl.entries[rl.ladderForIP(s.ip)[0].key].expiresAt = time.Now().Add(-time.Hour)
					rl.mu.Unlock()
				case opTake:
					allowed := 0
					for range s.takes {
						if rl.Take(s.ip) {
							allowed++
						}
					}
					if allowed != s.wantAllowed {
						t.Errorf("step %d %q: allowed = %d, want %d", i, s.ip, allowed, s.wantAllowed)
					}
				}
			}
		})
	}
}
