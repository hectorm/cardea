package ratelimit

import (
	"container/list"
	"net/netip"
	"sync"
	"time"
)

type RateLimit struct {
	MaxEntries int
	MaxCount   int
	Window     time.Duration
	entries    map[string]*RateLimitEntry
	lru        *list.List
	mu         sync.Mutex
}

type RateLimitEntry struct {
	key       string
	count     int
	expiresAt time.Time
	element   *list.Element
}

func NewRateLimit(maxEntries, maxCount int, window time.Duration) *RateLimit {
	return &RateLimit{
		MaxEntries: maxEntries,
		MaxCount:   maxCount,
		Window:     window,
		entries:    make(map[string]*RateLimitEntry),
		lru:        list.New(),
	}
}

func (rl *RateLimit) Take(ip string) bool {
	key := rl.keyForIP(ip)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	if entry, exists := rl.entries[key]; exists {
		rl.lru.MoveToFront(entry.element)
		if now.After(entry.expiresAt) {
			rl.resetEntryLocked(entry, now)
			return true
		}
		if entry.count >= rl.MaxCount {
			return false
		}
		entry.count++
		return true
	}

	rl.addEntryLocked(key, now)
	return true
}

func (rl *RateLimit) Reset(ip string) {
	key := rl.keyForIP(ip)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	if entry, exists := rl.entries[key]; exists {
		delete(rl.entries, entry.key)
		rl.lru.Remove(entry.element)
	}
}

func (rl *RateLimit) addEntryLocked(key string, now time.Time) {
	if rl.MaxEntries > 0 && rl.lru.Len() >= rl.MaxEntries {
		if oldest := rl.lru.Back(); oldest != nil {
			oldEntry := oldest.Value.(*RateLimitEntry)
			delete(rl.entries, oldEntry.key)
			rl.lru.Remove(oldest)
		}
	}

	entry := &RateLimitEntry{key: key}
	rl.resetEntryLocked(entry, now)
	entry.element = rl.lru.PushFront(entry)
	rl.entries[key] = entry
}

func (rl *RateLimit) resetEntryLocked(entry *RateLimitEntry, now time.Time) {
	entry.count = 1
	if rl.Window > 0 {
		entry.expiresAt = now.Add(rl.Window)
	} else {
		entry.expiresAt = now
	}
}

func (rl *RateLimit) keyForIP(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}

	addr = addr.Unmap().WithZone("")
	if addr.Is4() {
		return addr.String()
	}

	prefix, err := addr.Prefix(64)
	if err != nil {
		return addr.String()
	}
	return prefix.String()
}
