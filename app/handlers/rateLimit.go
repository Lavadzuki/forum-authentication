package handlers

import (
	"sync"
	"time"
)

type RateLimiter struct {
	mu            sync.Mutex
	requests      map[string]int
	limit         int
	resetInterval time.Duration
	resetTimes    map[string]time.Time
}

func NewRateLimiter(limit int, interval time.Duration) *RateLimiter {
	return &RateLimiter{
		requests:      make(map[string]int),
		limit:         limit,
		resetInterval: interval,
		resetTimes:    make(map[string]time.Time),
	}
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Сбросить счетчик запросов, если прошло достаточно времени
	if resetTime, exists := rl.resetTimes[ip]; !exists || time.Now().After(resetTime) {
		rl.requests[ip] = 0
		rl.resetTimes[ip] = time.Now().Add(rl.resetInterval)
	}

	// Проверка лимита запросов
	if rl.requests[ip] < rl.limit {
		rl.requests[ip]++
		return true
	}

	return false
}
