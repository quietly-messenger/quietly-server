// Package ratelimit implements a keyed token-bucket rate limiter. It is
// bounded: when the entry count exceeds a cap, the least-recently-used key is
// evicted, so memory cannot grow without bound (audit F-01, F-06).
package ratelimit

import (
	"sync"
	"time"
)

// Limiter is a keyed token bucket with FIFO eviction.
type Limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64 // bucket capacity
	max     int     // maximum distinct keys
	entries map[string]*entry
	order   []string // usage order, oldest first
}

type entry struct {
	tokens float64
	last   time.Time
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
	}
}

// Allow reports whether one token is available for key, consuming it if so.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	e, ok := l.entries[key]
	if !ok {
		for len(l.entries) >= l.max {
			oldest := l.order[0]
			l.order = l.order[1:]
			delete(l.entries, oldest)
		}
		e = &entry{tokens: l.burst, last: now}
		l.entries[key] = e
		l.order = append(l.order, key)
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
