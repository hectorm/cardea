package ratelimit

import (
	"container/list"
	"net/netip"
	"sync"
	"time"
)

type RateLimit struct {
	maxEntries   int
	maxCount     int
	window       time.Duration
	promoteAfter int
	v4PrefixBits []int
	v6PrefixBits []int
	entries      map[string]*entry
	lru          *list.List
	mu           sync.Mutex
}

type entry struct {
	key            string
	count          int
	parentNotified bool
	expiresAt      time.Time
	element        *list.Element
}

type level struct {
	key   string
	limit int
}

func NewRateLimit(maxEntries, maxCount int, window time.Duration) *RateLimit {
	return &RateLimit{
		maxEntries:   maxEntries,
		maxCount:     maxCount,
		window:       window,
		promoteAfter: 4,
		v4PrefixBits: []int{32},
		v6PrefixBits: []int{64, 56, 48},
		entries:      make(map[string]*entry),
		lru:          list.New(),
	}
}

func (rl *RateLimit) Take(ip string) bool {
	ladder := rl.ladderForIP(ip)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	for _, lv := range ladder {
		e, ok := rl.entries[lv.key]
		if !ok {
			continue
		}
		rl.lru.MoveToFront(e.element)
		if !now.After(e.expiresAt) && e.count >= lv.limit {
			return false
		}
	}

	for _, lv := range ladder {
		e := rl.entryLocked(lv.key, now)
		e.count++

		newlyBlocked := e.count >= lv.limit && !e.parentNotified
		if !newlyBlocked {
			break
		}
		e.parentNotified = true
	}

	return true
}

func (rl *RateLimit) Reset(ip string) {
	ladder := rl.ladderForIP(ip)
	if len(ladder) == 0 {
		return
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	if e, ok := rl.entries[ladder[0].key]; ok {
		delete(rl.entries, e.key)
		rl.lru.Remove(e.element)
	}
}

func (rl *RateLimit) entryLocked(key string, now time.Time) *entry {
	if e, ok := rl.entries[key]; ok {
		if now.After(e.expiresAt) {
			e.count = 0
			e.parentNotified = false
			e.expiresAt = rl.expiry(now)
		}
		rl.lru.MoveToFront(e.element)
		return e
	}

	if rl.maxEntries > 0 && rl.lru.Len() >= rl.maxEntries {
		if oldest := rl.lru.Back(); oldest != nil {
			oldEntry := oldest.Value.(*entry)
			delete(rl.entries, oldEntry.key)
			rl.lru.Remove(oldest)
		}
	}

	e := &entry{key: key, expiresAt: rl.expiry(now)}
	e.element = rl.lru.PushFront(e)
	rl.entries[key] = e
	return e
}

func (rl *RateLimit) expiry(now time.Time) time.Time {
	if rl.window > 0 {
		return now.Add(rl.window)
	}
	return now
}

func (rl *RateLimit) ladderForIP(ip string) []level {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return []level{{key: ip, limit: rl.maxCount}}
	}

	addr = addr.Unmap().WithZone("")

	prefixBits := rl.v4PrefixBits
	if addr.Is6() {
		prefixBits = rl.v6PrefixBits
	}

	ladder := make([]level, 0, len(prefixBits))
	for i, bits := range prefixBits {
		prefix, err := addr.Prefix(bits)
		if err != nil {
			continue
		}
		limit := rl.promoteAfter
		if i == 0 {
			limit = rl.maxCount
		}
		ladder = append(ladder, level{key: prefix.String(), limit: limit})
	}
	if len(ladder) == 0 {
		ladder = append(ladder, level{key: addr.String(), limit: rl.maxCount})
	}
	return ladder
}
