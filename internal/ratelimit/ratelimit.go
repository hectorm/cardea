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
	mu         sync.RWMutex
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

func (rl *RateLimit) Allow(ip string) bool {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	now := time.Now()
	if entry, exists := rl.entries[ip]; exists {
		if now.After(entry.expiresAt) {
			return true
		}
		return entry.count < rl.MaxCount
	}

	return true
}

func (rl *RateLimit) Failure(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	if entry, exists := rl.entries[ip]; exists {
		rl.lru.MoveToFront(entry.element)
		if now.After(entry.expiresAt) {
			entry.count = 1
			entry.expiresAt = now.Add(rl.Window)
		} else {
			entry.count++
		}
		return
	}

	if rl.lru.Len() >= rl.MaxEntries {
		oldest := rl.lru.Back()
		if oldest != nil {
			oldEntry := oldest.Value.(*RateLimitEntry)
			delete(rl.entries, oldEntry.ip)
			rl.lru.Remove(oldest)
		}
	}

	entry := &RateLimitEntry{
		ip:        ip,
		count:     1,
		expiresAt: now.Add(rl.Window),
	}
	entry.element = rl.lru.PushFront(entry)
	rl.entries[ip] = entry
}

func (rl *RateLimit) Reset(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if entry, exists := rl.entries[ip]; exists {
		delete(rl.entries, entry.ip)
		rl.lru.Remove(entry.element)
	}
}
