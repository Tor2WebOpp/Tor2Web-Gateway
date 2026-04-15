package proxy

import (
	"net"
	"net/http"
	"sync"
	"time"

	"gateway/internal/config"

	"golang.org/x/time/rate"
)

// visitor holds per-IP rate limiter state.
type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// RateLimiter enforces per-IP and global request rate limits.
type RateLimiter struct {
	visitors sync.Map
	global   *rate.Limiter
	cfg      *config.RateLimitConf
}

// newGlobalLimiter creates the global rate.Limiter from config.
func newGlobalLimiter(cfg *config.RateLimitConf) *rate.Limiter {
	burst := int(cfg.GlobalRPS)
	if burst < cfg.PerIPBurst {
		burst = cfg.PerIPBurst
	}
	return rate.NewLimiter(rate.Limit(cfg.GlobalRPS), burst)
}

// NewRateLimiter creates a RateLimiter and starts the cleanup goroutine.
func NewRateLimiter(cfg *config.RateLimitConf) *RateLimiter {
	rl := &RateLimiter{
		global: newGlobalLimiter(cfg),
		cfg:    cfg,
	}
	go rl.cleanup()
	return rl
}

// getLimiter returns (creating if necessary) the per-IP rate limiter for ip.
func (rl *RateLimiter) getLimiter(ip string) *rate.Limiter {
	now := time.Now()
	v := &visitor{
		limiter:  rate.NewLimiter(rate.Limit(rl.cfg.PerIPRPS), rl.cfg.PerIPBurst),
		lastSeen: now,
	}
	actual, _ := rl.visitors.LoadOrStore(ip, v)
	vis := actual.(*visitor)
	vis.lastSeen = now
	return vis.limiter
}

// cleanup runs on a ticker and removes visitors idle for more than 10 minutes.
func (rl *RateLimiter) cleanup() {
	interval := rl.cfg.CleanupInterval
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-10 * time.Minute)
		rl.visitors.Range(func(k, v any) bool {
			if v.(*visitor).lastSeen.Before(cutoff) {
				rl.visitors.Delete(k)
			}
			return true
		})
	}
}

// Middleware returns an http.Handler that enforces rate limits before calling next.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.global.Allow() {
			w.Header().Set("Retry-After", "3")
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		ip := clientIP(r)
		lim := rl.getLimiter(ip)
		if !lim.Allow() {
			w.Header().Set("Retry-After", "3")
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// clientIP extracts the client IP, preferring CF-Connecting-IP over RemoteAddr.
func clientIP(r *http.Request) string {
	if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
		return cf
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
