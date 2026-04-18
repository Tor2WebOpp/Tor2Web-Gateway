package proxy

import (
	"bytes"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCFValidator_KnownRange(t *testing.T) {
	v := &CFValidator{enabled: true}
	_, cidr, _ := net.ParseCIDR("173.245.48.0/20")
	v.nets = []*net.IPNet{cidr}

	if !v.IsCloudflareIP("173.245.48.1") {
		t.Error("should accept CF IP")
	}
	if v.IsCloudflareIP("1.2.3.4") {
		t.Error("should reject non-CF IP")
	}
}

func TestCFValidator_Disabled(t *testing.T) {
	v := &CFValidator{enabled: false}
	if !v.IsCloudflareIP("1.2.3.4") {
		t.Error("disabled validator should accept all")
	}
}

// TestCFValidator_Middleware_HashesRejectedIP verifies that when a request
// is rejected for originating outside the CF range, the log line contains
// the hasher's output (not the raw IP). Regression guard for OPSEC leak
// #3: raw client IPs must never reach slog sinks.
func TestCFValidator_Middleware_HashesRejectedIP(t *testing.T) {
	v := &CFValidator{enabled: true}
	_, cidr, _ := net.ParseCIDR("173.245.48.0/20")
	v.nets = []*net.IPNet{cidr}

	hasher := func(ip string) string { return "hashed:" + ip[:1] }
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := v.Middleware(hasher, next)

	// Redirect slog so we can inspect what was logged.
	prev := slog.Default()
	buf := &bytes.Buffer{}
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.99:42000"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", rr.Code)
	}
	logged := buf.String()
	if strings.Contains(logged, "203.0.113.99") {
		t.Errorf("raw client IP leaked into log:\n%s", logged)
	}
	if !strings.Contains(logged, "hashed:2") {
		t.Errorf("expected hasher output in log:\n%s", logged)
	}
}

// TestCFValidator_Middleware_NilHasherPassthrough documents the legacy
// behaviour: passing nil hashIP preserves the raw-IP log line used by
// pre-OPSEC callers. The production NewServer always wires a non-nil
// hasher when a labeler is available.
func TestCFValidator_Middleware_NilHasherPassthrough(t *testing.T) {
	v := &CFValidator{enabled: true}
	_, cidr, _ := net.ParseCIDR("173.245.48.0/20")
	v.nets = []*net.IPNet{cidr}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := v.Middleware(nil, next)

	prev := slog.Default()
	buf := &bytes.Buffer{}
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.99:42000"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", rr.Code)
	}
	if !strings.Contains(buf.String(), "203.0.113.99") {
		t.Errorf("expected raw IP in log when hasher is nil:\n%s", buf.String())
	}
}
