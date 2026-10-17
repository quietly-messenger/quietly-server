// Package ratelimit implements a keyed token-bucket rate limiter. It is
// bounded: when the entry count exceeds a cap, the least-recently-used key is
// evicted, so memory cannot grow without bound and a flood of one-off keys
// cannot push out clients that are actively making requests (audit F-01, F-23).
package ratelimit

import (
	"container/list"
	"sync"
	"time"
)

// Limiter is a keyed token bucket with LRU eviction.
type Limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64 // bucket capacity
	max     int     // maximum distinct keys
	entries map[string]*entry
	lru     *list.List // front = least recently used; values are keys
}

type entry struct {
	tokens float64
	last   time.Time
	elem   *list.Element
}

// New builds a limiter allowing ratePerSec tokens per second with a burst of
// burst, tracking at most max distinct keys.
func New(ratePerSec float64, burst, max int) *Limiter {
	if burst < 1 {
		burst = 1
	}
	if max < 1 {
		max = 1
	}
	return &Limiter{
		rate:    ratePerSec,
		burst:   float64(burst),
		max:     max,
		entries: make(map[string]*entry),
		lru:     list.New(),
	}
}

// Allow reports whether one token is available for key, consuming it if so.
// Every call marks the key as most recently used.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	e, ok := l.entries[key]
	if !ok {
		for len(l.entries) >= l.max {
			oldest := l.lru.Front()
			if oldest == nil {
				break
			}
			l.lru.Remove(oldest)
			delete(l.entries, oldest.Value.(string))
		}
		e = &entry{tokens: l.burst, last: now}
		e.elem = l.lru.PushBack(key)
		l.entries[key] = e
	} else {
		l.lru.MoveToBack(e.elem)
	}

	e.tokens += now.Sub(e.last).Seconds() * l.rate
	if e.tokens > l.burst {
		e.tokens = l.burst
	}
	e.last = now

	if e.tokens < 1 {
		return false
	}
	e.tokens--
	return true
}
