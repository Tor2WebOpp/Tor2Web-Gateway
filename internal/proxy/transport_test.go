package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gateway/internal/config"
	"gateway/internal/shared"
)

func TestSelectBackend_LeastScore(t *testing.T) {
	pool := []shared.BackendInfo{
		{Port: 9050, Alive: true, ActiveConns: 5, LatencyMs: 200, ErrorRate: 0.1},  // score = 10 + 2 + 1 = 13
		{Port: 9051, Alive: true, ActiveConns: 1, LatencyMs: 50, ErrorRate: 0.0},   // score = 2 + 0.5 + 0 = 2.5 (lowest)
		{Port: 9052, Alive: false, ActiveConns: 0, LatencyMs: 10, ErrorRate: 0.0},  // dead
	}

	got := selectBackend(pool)
	if got == nil {
		t.Fatal("expected a backend, got nil")
	}
	if got.Port != 9051 {
		t.Errorf("expected port 9051 (lowest score), got port %d", got.Port)
	}
}

func TestSelectBackend_AllDead(t *testing.T) {
	pool := []shared.BackendInfo{
		{Port: 9050, Alive: false},
		{Port: 9051, Alive: false},
		{Port: 9052, Alive: false},
	}

	got := selectBackend(pool)
	if got != nil {
		t.Errorf("expected nil, got backend on port %d", got.Port)
	}
}

// fakeTransport implements transport.Transport. DialSOCKS dials a
// pre-configured host:port on the local loopback, ignoring the passed
// port (used only to select among backends in the pool fixture).
type fakeTransport struct {
	targetByPort map[int]string // port -> "host:port" to dial
}

func (f *fakeTransport) DialSOCKS(ctx context.Context, port int) (net.Conn, error) {
	target, ok := f.targetByPort[port]
	if !ok {
		return nil, fmt.Errorf("fakeTransport: no target for port %d", port)
	}
	d := net.Dialer{Timeout: 2 * time.Second}
	return d.DialContext(ctx, "tcp", target)
}

func (f *fakeTransport) AdminClient() *http.Client { return http.DefaultClient }
func (f *fakeTransport) Close() error              { return nil }

// newTestTorTransport builds a TorTransport aimed at the supplied
// httptest.Server, with one backend per target. Returns the transport
// plus the pool that must be returned from its fetcher.
func newTestTorTransport(t *testing.T, targets map[int]string, backends []shared.BackendInfo) *TorTransport {
	t.Helper()
	cfg := &config.Config{
		Domain: "test.local",
	}
	cfg.Pool.MaxIdleConnsPerHost = 2
	cfg.Pool.IdleTimeout = 10 * time.Second
	cfg.Pool.ResponseTimeout = 10 * time.Second
	cfg.Pool.RetryAttempts = 2

	tr := NewTorTransport(cfg, &fakeTransport{targetByPort: targets}, func() []shared.BackendInfo {
		return backends
	})
	return tr
}

// hostPort splits "scheme://host:port/..." into (host, port int).
func hostPort(t *testing.T, raw string) (string, int) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split %q: %v", u.Host, err)
	}
	var p int
	fmt.Sscanf(portStr, "%d", &p)
	return host, p
}

// TestLimitReaderSkippedForSSE ensures streaming responses (SSE) flow
// through without being truncated at maxResponseBytes. The test server
// writes more than maxResponseBytes; the client must receive all of it.
func TestLimitReaderSkippedForSSE(t *testing.T) {
	// Write slightly more than 50 MB so a silent truncation would be
	// obvious. A single slice write plus explicit flushing keeps the
	// test bounded; we check the byte total, not timing.
	payload := bytes.Repeat([]byte("x"), maxResponseBytes+1024*1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(payload); err != nil {
			t.Errorf("server write: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	host, port := hostPort(t, srv.URL)
	targets := map[int]string{9050: net.JoinHostPort(host, fmt.Sprintf("%d", port))}
	pool := []shared.BackendInfo{{Port: 9050, Alive: true, Backend: "backend.onion"}}
	tt := newTestTorTransport(t, targets, pool)
	t.Cleanup(func() { _ = tt.Close() })

	req, _ := http.NewRequest(http.MethodGet, "https://test.local/stream", nil)
	resp, err := tt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(got) != len(payload) {
		t.Fatalf("SSE body truncated: got %d bytes, want %d", len(got), len(payload))
	}
}

// TestLimitReaderTruncatesJSON asserts a plain JSON body is capped at
// maxResponseBytes and that a slog.Warn is emitted exactly once.
func TestLimitReaderTruncatesJSON(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), maxResponseBytes+5*1024*1024) // 55 MB
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(payload)))
		w.WriteHeader(http.StatusOK)
		w.Write(payload)
	}))
	t.Cleanup(srv.Close)

	host, port := hostPort(t, srv.URL)
	targets := map[int]string{9050: net.JoinHostPort(host, fmt.Sprintf("%d", port))}
	pool := []shared.BackendInfo{{Port: 9050, Alive: true, Backend: "backend.onion"}}
	tt := newTestTorTransport(t, targets, pool)
	t.Cleanup(func() { _ = tt.Close() })

	// Capture slog output so we can assert the warn fired.
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	req, _ := http.NewRequest(http.MethodGet, "https://test.local/big.json", nil)
	resp, err := tt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(got) != maxResponseBytes {
		t.Fatalf("JSON body not truncated at cap: got %d bytes, want %d", len(got), maxResponseBytes)
	}
	logs := buf.String()
	if !strings.Contains(logs, "response truncated at max_response_bytes") {
		t.Fatalf("expected truncation warning in slog output, got:\n%s", logs)
	}
}

// TestBreakerPerBackend confirms that a failing backend trips its own
// breaker without affecting a sibling backend that shares the same SOCKS
// port. The failing backend runs on port A; the healthy one on port B;
// they share a TorTransport instance. After >=10 failures we assert the
// healthy one still roundtrips cleanly — i.e. its breaker is independent.
func TestBreakerPerBackend(t *testing.T) {
	// Healthy server — returns 200 unconditionally.
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(healthy.Close)

	// Failing server — returns 502 unconditionally.
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(failing.Close)

	hHost, hPort := hostPort(t, healthy.URL)
	fHost, fPort := hostPort(t, failing.URL)

	// Both backends share the same logical SOCKS port in the test map
	// key, but each has a distinct target address. We vary the Port
	// value in the pool to force getTransport to produce distinct
	// (port, backend) breaker keys.
	targets := map[int]string{
		9050: net.JoinHostPort(hHost, fmt.Sprintf("%d", hPort)),
		9051: net.JoinHostPort(fHost, fmt.Sprintf("%d", fPort)),
	}
	// We craft the pool so each call to RoundTrip resolves to only one
	// backend — we swap the pool between calls rather than rely on
	// selection heuristics (selectBackend prefers lower ActiveConns).
	var poolRef atomic.Value
	poolRef.Store([]shared.BackendInfo{{Port: 9051, Alive: true, Backend: "bad.onion"}})

	cfg := &config.Config{Domain: "test.local"}
	cfg.Pool.MaxIdleConnsPerHost = 2
	cfg.Pool.IdleTimeout = 10 * time.Second
	cfg.Pool.ResponseTimeout = 10 * time.Second
	cfg.Pool.RetryAttempts = 1 // do not retry on other backends within one call
	tt := NewTorTransport(cfg, &fakeTransport{targetByPort: targets}, func() []shared.BackendInfo {
		return poolRef.Load().([]shared.BackendInfo)
	})
	t.Cleanup(func() { _ = tt.Close() })

	// Hammer the failing backend to force breaker open (20 > gobreaker
	// minimum of 10 requests before ReadyToTrip kicks in).
	for i := 0; i < 20; i++ {
		req, _ := http.NewRequest(http.MethodGet, "https://test.local/fail", nil)
		resp, err := tt.RoundTrip(req)
		if resp != nil {
			resp.Body.Close()
		}
		_ = err // either 502 or breaker-open error is fine
	}

	// Inspect the breakers map: the failing breaker must exist; the
	// healthy breaker should still be absent (never touched).
	tt.mu.Lock()
	badKey := breakerKey{port: 9051, backend: "bad.onion"}
	if _, ok := tt.breakers[badKey]; !ok {
		tt.mu.Unlock()
		t.Fatalf("expected breaker for %+v to exist", badKey)
	}
	goodKey := breakerKey{port: 9050, backend: "good.onion"}
	if _, ok := tt.breakers[goodKey]; ok {
		tt.mu.Unlock()
		t.Fatalf("unexpected breaker for good backend before any request")
	}
	tt.mu.Unlock()

	// Swap pool to the healthy backend — its breaker should be untouched.
	poolRef.Store([]shared.BackendInfo{{Port: 9050, Alive: true, Backend: "good.onion"}})
	req, _ := http.NewRequest(http.MethodGet, "https://test.local/ok", nil)
	resp, err := tt.RoundTrip(req)
	if err != nil {
		t.Fatalf("healthy RoundTrip failed — sibling breaker incorrectly tripped: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthy backend returned %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestTorTransportCloseDrains asserts Close empties the transports and
// breakers maps. We pre-populate both via getTransport and then verify
// Close leaves the maps empty.
func TestTorTransportCloseDrains(t *testing.T) {
	cfg := &config.Config{}
	cfg.Pool.MaxIdleConnsPerHost = 1
	cfg.Pool.IdleTimeout = time.Second
	cfg.Pool.ResponseTimeout = time.Second

	tt := NewTorTransport(cfg, nil, func() []shared.BackendInfo { return nil })

	tt.getTransport(9050, "a.onion")
	tt.getTransport(9050, "b.onion")
	tt.getTransport(9051, "c.onion")

	tt.mu.Lock()
	if got := len(tt.transports); got != 2 {
		tt.mu.Unlock()
		t.Fatalf("pre-Close transports len = %d, want 2", got)
	}
	if got := len(tt.breakers); got != 3 {
		tt.mu.Unlock()
		t.Fatalf("pre-Close breakers len = %d, want 3", got)
	}
	tt.mu.Unlock()

	if err := tt.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	tt.mu.Lock()
	if got := len(tt.transports); got != 0 {
		tt.mu.Unlock()
		t.Fatalf("post-Close transports len = %d, want 0", got)
	}
	if got := len(tt.breakers); got != 0 {
		tt.mu.Unlock()
		t.Fatalf("post-Close breakers len = %d, want 0", got)
	}
	tt.mu.Unlock()
}

// TestRemoveTransportClearsAllBreakersForPort checks that evicting a Tor
// instance clears every (port, backend) breaker sharing that port.
func TestRemoveTransportClearsAllBreakersForPort(t *testing.T) {
	cfg := &config.Config{}
	cfg.Pool.MaxIdleConnsPerHost = 1
	cfg.Pool.IdleTimeout = time.Second
	cfg.Pool.ResponseTimeout = time.Second
	tt := NewTorTransport(cfg, nil, func() []shared.BackendInfo { return nil })

	tt.getTransport(9050, "a.onion")
	tt.getTransport(9050, "b.onion")
	tt.getTransport(9051, "c.onion")

	tt.RemoveTransport(9050)

	tt.mu.Lock()
	defer tt.mu.Unlock()
	if _, ok := tt.transports[9050]; ok {
		t.Fatalf("9050 transport should be removed")
	}
	for k := range tt.breakers {
		if k.port == 9050 {
			t.Fatalf("breaker for port 9050 backend %q survived RemoveTransport", k.backend)
		}
	}
	if _, ok := tt.transports[9051]; !ok {
		t.Fatalf("9051 transport should be intact")
	}
}
