package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"gateway/internal/config"
)

func newTestRateLimiter(rps float64, burst int) *RateLimiter {
	cfg := &config.RateLimitConf{
		PerIPRPS:        rps,
		PerIPBurst:      burst,
		GlobalRPS:       1000,
		CleanupInterval: 0, // no-op; cleanup goroutine uses default
	}
	// Don't start cleanup goroutine in tests to avoid goroutine leaks.
	rl := &RateLimiter{
		global: newGlobalLimiter(cfg),
		cfg:    cfg,
	}
	return rl
}

func TestRateLimiter_AllowsNormal(t *testing.T) {
	rl := newTestRateLimiter(10, 20)

	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestRateLimiter_Blocks(t *testing.T) {
	rl := newTestRateLimiter(1, 1)

	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.RemoteAddr = "5.6.7.8:5678"
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "5.6.7.8:5678"
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	if rr1.Code != http.StatusOK {
		t.Errorf("first request: expected 200, got %d", rr1.Code)
	}
	if rr2.Code != http.StatusTooManyRequests {
		t.Errorf("second request: expected 429, got %d", rr2.Code)
	}
}
