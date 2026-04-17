package proxy

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gateway/internal/config"

	"golang.org/x/time/rate"
)

// connTracker tracks concurrent connections for a single IP.
type connTracker struct {
	count atomic.Int64
}

// visitor holds per-IP rate limiter state.
type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
	mu       sync.Mutex
}

// RateLimiter enforces per-IP and global request rate limits.
type RateLimiter struct {
	visitors    sync.Map // ip -> *visitor  (general)
	apiVisitors sync.Map // ip -> *visitor  (for /api/ routes)
	connCounts  sync.Map // ip -> *connTracker
	global      *rate.Limiter
	cfg         *config.RateLimitConf
	done        chan struct{}
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
		done:   make(chan struct{}),
	}
	go rl.cleanup()
	return rl
}

// Stop shuts down the background cleanup goroutine.
func (rl *RateLimiter) Stop() {
	close(rl.done)
}

// getLimiter returns (creating if necessary) the per-IP rate limiter for ip.
func (rl *RateLimiter) getLimiter(ip string) *rate.Limiter {
	now := time.Now()
	if val, ok := rl.visitors.Load(ip); ok {
		v := val.(*visitor)
		v.mu.Lock()
		v.lastSeen = now
		v.mu.Unlock()
		return v.limiter
	}
	v := &visitor{
		limiter:  rate.NewLimiter(rate.Limit(rl.cfg.PerIPRPS), rl.cfg.PerIPBurst),
		lastSeen: now,
	}
	actual, _ := rl.visitors.LoadOrStore(ip, v)
	return actual.(*visitor).limiter
}

// getAPILimiter returns a stricter per-IP rate limiter for /api/ routes.
func (rl *RateLimiter) getAPILimiter(ip string) *rate.Limiter {
	now := time.Now()
	if val, ok := rl.apiVisitors.Load(ip); ok {
		v := val.(*visitor)
		v.mu.Lock()
		v.lastSeen = now
		v.mu.Unlock()
		return v.limiter
	}
	v := &visitor{
		limiter:  rate.NewLimiter(rate.Limit(rl.cfg.APIRPS), rl.cfg.APIBurst),
		lastSeen: now,
	}
	actual, _ := rl.apiVisitors.LoadOrStore(ip, v)
	return actual.(*visitor).limiter
}

// getConnTracker returns (creating if necessary) the connection tracker for ip.
func (rl *RateLimiter) getConnTracker(ip string) *connTracker {
	if val, ok := rl.connCounts.Load(ip); ok {
		return val.(*connTracker)
	}
	ct := &connTracker{}
	actual, _ := rl.connCounts.LoadOrStore(ip, ct)
	return actual.(*connTracker)
}

// cleanup runs on a ticker and removes visitors idle for more than 10 minutes.
func (rl *RateLimiter) cleanup() {
	interval := rl.cfg.CleanupInterval
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	cleanMap := func(m *sync.Map) {
		cutoff := time.Now().Add(-10 * time.Minute)
		m.Range(func(k, v any) bool {
			vis := v.(*visitor)
			vis.mu.Lock()
			lastSeen := vis.lastSeen
			vis.mu.Unlock()
			if lastSeen.Before(cutoff) {
				m.Delete(k)
			}
			return true
		})
	}

	for {
		select {
		case <-rl.done:
			return
		case <-ticker.C:
			cleanMap(&rl.visitors)
			cleanMap(&rl.apiVisitors)
		}
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

		// Per-IP connection limit (skip when PerIPConns is not configured).
		if rl.cfg.PerIPConns > 0 {
			tracker := rl.getConnTracker(ip)
			if tracker.count.Load() >= int64(rl.cfg.PerIPConns) {
				w.Header().Set("Retry-After", "3")
				http.Error(w, "Too Many Connections", http.StatusTooManyRequests)
				return
			}
			tracker.count.Add(1)
			defer tracker.count.Add(-1)
		}

		// Route-specific rate limiting: stricter for /api/ paths.
		if strings.HasPrefix(r.URL.Path, "/api/") && rl.cfg.APIRPS > 0 {
			apiLim := rl.getAPILimiter(ip)
			if !apiLim.Allow() {
				w.Header().Set("Retry-After", "3")
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
		} else {
			lim := rl.getLimiter(ip)
			if !lim.Allow() {
				w.Header().Set("Retry-After", "3")
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
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
