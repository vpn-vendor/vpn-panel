package ratelimit

import (
	"sync"
	"time"
)

type Limiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	burst    float64
	refill   float64
	lastTidy time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func New(burst int, refillPer int, period time.Duration) *Limiter {
	return &Limiter{
		buckets:  make(map[string]*bucket),
		burst:    float64(burst),
		refill:   float64(refillPer) / period.Seconds(),
		lastTidy: time.Now(),
	}
}

func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.fill(key)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *Limiter) Ready(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.fill(key).tokens >= 1
}

func (l *Limiter) RetryIn(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.fill(key)
	if b.tokens >= 1 || l.refill <= 0 {
		return 0
	}
	return time.Duration((1 - b.tokens) / l.refill * float64(time.Second))
}

func (l *Limiter) Charge(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if b := l.fill(key); b.tokens >= 1 {
		b.tokens--
	}
}

func (l *Limiter) fill(key string) *bucket {
	now := time.Now()
	l.tidy(now)
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.refill
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	return b
}

func (l *Limiter) tidy(now time.Time) {
	if now.Sub(l.lastTidy) < time.Minute {
		return
	}
	l.lastTidy = now
	for k, b := range l.buckets {
		idle := now.Sub(b.last)
		if b.tokens+idle.Seconds()*l.refill >= l.burst && idle > time.Minute {
			delete(l.buckets, k)
		}
	}
}
