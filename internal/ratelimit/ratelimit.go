package ratelimit

import (
	"container/list"
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
	ip        string
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
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	if entry, exists := rl.entries[ip]; exists {
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

	rl.addEntryLocked(ip, now)
	return true
}

func (rl *RateLimit) addEntryLocked(ip string, now time.Time) {
	if rl.MaxEntries > 0 && rl.lru.Len() >= rl.MaxEntries {
		if oldest := rl.lru.Back(); oldest != nil {
			oldEntry := oldest.Value.(*RateLimitEntry)
			delete(rl.entries, oldEntry.ip)
			rl.lru.Remove(oldest)
		}
	}

	entry := &RateLimitEntry{ip: ip}
	rl.resetEntryLocked(entry, now)
	entry.element = rl.lru.PushFront(entry)
	rl.entries[ip] = entry
}

func (rl *RateLimit) resetEntryLocked(entry *RateLimitEntry, now time.Time) {
	entry.count = 1
	if rl.Window > 0 {
		entry.expiresAt = now.Add(rl.Window)
	} else {
		entry.expiresAt = now
	}
}

func (rl *RateLimit) Reset(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if entry, exists := rl.entries[ip]; exists {
		delete(rl.entries, entry.ip)
		rl.lru.Remove(entry.element)
	}
}
