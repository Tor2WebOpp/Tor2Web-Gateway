package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gateway/internal/config"
	"gateway/internal/shared"
)

// captureRT is an http.RoundTripper that records the request it sees and
// returns a synthetic 204 response. Used by the Director tests to assert
// what would actually reach the backend.
type captureRT struct {
	got *http.Request
}

func (c *captureRT) RoundTrip(r *http.Request) (*http.Response, error) {
	c.got = r.Clone(context.Background())
	return &http.Response{
		StatusCode: http.StatusNoContent,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     http.Header{},
	}, nil
}

// runDirector wraps the Director under test in a httputil.ReverseProxy,
// fires req through it, and returns the request the inner RoundTripper
// observed (i.e. what would have reached the backend).
func runDirector(t *testing.T, cfEnabled bool, req *http.Request) *http.Request {
	t.Helper()
	cap := &captureRT{}
	rp := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			stripInboundProxyHeaders(r.Header, cfEnabled)
			// Director must rewrite URL or ReverseProxy panics on nil scheme.
			if r.URL.Scheme == "" {
				r.URL.Scheme = "http"
				r.URL.Host = "backend.invalid"
			}
		},
		Transport: cap,
	}
	rec := newDiscardWriter()
	rp.ServeHTTP(rec, req)
	if cap.got == nil {
		t.Fatalf("director never reached transport")
	}
	return cap.got
}

// discardWriter implements http.ResponseWriter and throws away everything.
type discardWriter struct {
	hdr http.Header
}

func newDiscardWriter() *discardWriter             { return &discardWriter{hdr: http.Header{}} }
func (d *discardWriter) Header() http.Header       { return d.hdr }
func (d *discardWriter) Write(b []byte) (int, error) { return len(b), nil }
func (d *discardWriter) WriteHeader(int)             {}

// TestStripInboundProxyHeaders_SpoofedHeadersGone is a focused regression
// for P1: every header an attacker can spoof to forge auth context must
// be removed by the Director before TorTransport.RoundTrip stamps the
// trusted X-Forwarded-For value.
func TestStripInboundProxyHeaders_SpoofedHeadersGone(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://victim.example/", nil)
	for k, v := range map[string]string{
		"X-Real-IP":           "127.0.0.1",
		"X-Forwarded-For":     "127.0.0.1",
		"Forwarded":           "for=10.0.0.1",
		"True-Client-IP":      "127.0.0.1",
		"X-Forwarded-Host":    "internal.victim",
		"X-Forwarded-Proto":   "http",
		"X-Forwarded-Port":    "8080",
		"X-Real-Port":         "8080",
		"X-Original-URL":      "/admin",
		"X-Rewrite-URL":       "/admin",
		"X-Original-Host":     "internal.victim",
		"CF-Ray":              "spoofed-ray",
		"CF-Visitor":          `{"scheme":"http"}`,
		"Fastly-Client-IP":    "127.0.0.1",
		"X-Client-IP":         "127.0.0.1",
		"X-Cluster-Client-IP": "127.0.0.1",
		"Via":                 "1.1 attacker",
		"X-Proxy-Secret":      "stolen",
	} {
		req.Header.Set(k, v)
	}

	got := runDirector(t, false, req)

	for _, h := range []string{
		"X-Real-IP", "X-Forwarded-For", "Forwarded", "True-Client-IP",
		"X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port", "X-Real-Port",
		"X-Original-URL", "X-Rewrite-URL", "X-Original-Host",
		"CF-Ray", "CF-Visitor", "Fastly-Client-IP", "X-Client-IP",
		"X-Cluster-Client-IP", "Via", "X-Proxy-Secret",
	} {
		if v := got.Header.Get(h); v != "" {
			t.Errorf("header %q leaked through Director: %q", h, v)
		}
	}
}

// TestStripInboundProxyHeaders_CFOff_StripsCFConnectingIP confirms the
// policy choice: when Cloudflare is OFF nothing has validated the peer,
// so an attacker's CF-Connecting-IP must not survive.
func TestStripInboundProxyHeaders_CFOff_StripsCFConnectingIP(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://victim.example/", nil)
	req.Header.Set("CF-Connecting-IP", "127.0.0.1")

	got := runDirector(t, false, req)
	if v := got.Header.Get("CF-Connecting-IP"); v != "" {
		t.Errorf("CF-Connecting-IP must be stripped when CF is off; got %q", v)
	}
}

// TestStripInboundProxyHeaders_CFOn_PreservesCFConnectingIP confirms the
// other branch of the policy: when CF is on, CFValidator upstream has
// already verified the peer is in CF range, so we keep the header for
// TorTransport.RoundTrip to copy into X-Forwarded-For.
func TestStripInboundProxyHeaders_CFOn_PreservesCFConnectingIP(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://victim.example/", nil)
	req.Header.Set("CF-Connecting-IP", "203.0.113.99")

	got := runDirector(t, true, req)
	if v := got.Header.Get("CF-Connecting-IP"); v != "203.0.113.99" {
		t.Errorf("CF-Connecting-IP must survive when CF is on; got %q", v)
	}
}

// TestNewRedirectServer_HasTimeouts is the structural regression guard
// for P13: the production-configured *http.Server constructor must keep
// every timeout non-zero. A zero ReadHeaderTimeout would re-introduce
// the slowloris -> ACME-renewal-break failure mode.
func TestNewRedirectServer_HasTimeouts(t *testing.T) {
	srv := newRedirectServer(":0", "example.com")
	if srv.ReadHeaderTimeout <= 0 {
		t.Errorf("ReadHeaderTimeout must be > 0 (slowloris fix); got %v", srv.ReadHeaderTimeout)
	}
	if srv.ReadTimeout <= 0 {
		t.Errorf("ReadTimeout must be > 0; got %v", srv.ReadTimeout)
	}
	if srv.WriteTimeout <= 0 {
		t.Errorf("WriteTimeout must be > 0; got %v", srv.WriteTimeout)
	}
	if srv.IdleTimeout <= 0 {
		t.Errorf("IdleTimeout must be > 0; got %v", srv.IdleTimeout)
	}
	if srv.Handler == nil {
		t.Error("redirect server must have a handler")
	}
}

// TestRedirectServer_ReadHeaderTimeout_ClosesIdleConn boots the real
// production-configured redirect server on an ephemeral port, opens a
// raw TCP connection without sending any bytes, and asserts the server
// closes it within ReadHeaderTimeout. Behavioural complement to the
// structural test above.
func TestRedirectServer_ReadHeaderTimeout_ClosesIdleConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := newRedirectServer(ln.Addr().String(), "example.com")
	// Override ReadHeaderTimeout to keep the test snappy; the prod value
	// (2s) would slow CI without changing behaviour.
	srv.ReadHeaderTimeout = 200 * time.Millisecond
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Do not send any bytes. Expect the server to close after roughly
	// ReadHeaderTimeout. Read should return EOF (or timeout) within a
	// generous bound; without the fix, it would hang until our deadline.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatalf("expected connection close after ReadHeaderTimeout, got data")
	}
	if !errors.Is(err, io.EOF) {
		// Some platforms surface a connection-reset rather than EOF;
		// either is acceptable evidence the server tore the conn down.
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatalf("server did not close conn after ReadHeaderTimeout: %v", err)
		}
	}
}

// blockingManager is a certManager fake whose ManageSync blocks until
// the caller's context is cancelled. It lets TestListenAndServeTLS_ManageSyncTimeout
// assert that unbounded ACME orders no longer freeze startup.
type blockingManager struct {
	started atomic.Int32
}

func (b *blockingManager) ManageSync(ctx context.Context, _ []string) error {
	b.started.Add(1)
	<-ctx.Done()
	return ctx.Err()
}

func (b *blockingManager) TLSConfig() *tls.Config {
	return &tls.Config{}
}

// TestListenAndServeTLS_ManageSyncTimeout is the regression for Bug 2.1:
// without the fix, listenAndServeTLSWithManager used
// context.Background() and would wait forever for ACME. With the fix in
// place the deadline is observed and the helper returns a wrapped
// context.DeadlineExceeded error well inside 2x the configured margin.
func TestListenAndServeTLS_ManageSyncTimeout(t *testing.T) {
	t.Parallel()

	s := &Server{httpServer: &http.Server{}}

	// Shrink the surrounding context so the test is bounded; the real
	// manageSyncTimeout is 60s, which would turn this into an
	// unacceptable CI timer. The wider deadline (400ms) gives
	// listenAndServeTLSWithManager time to return after its inner
	// ManageSync context fires.
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	bm := &blockingManager{}

	errCh := make(chan error, 1)
	start := time.Now()
	go func() {
		errCh <- s.listenAndServeTLSWithManager(ctx, "example.test", bm)
	}()

	select {
	case err := <-errCh:
		elapsed := time.Since(start)
		if err == nil {
			t.Fatalf("expected timeout error, got nil (elapsed %s)", elapsed)
		}
		if !strings.Contains(err.Error(), "certmagic manage") {
			t.Fatalf("error should mention certmagic manage, got %v", err)
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected wrapped DeadlineExceeded, got %v", err)
		}
		// 2x margin: the outer ctx is 400ms, so anything under 800ms
		// is fine. Without the fix this would block indefinitely.
		if elapsed > 800*time.Millisecond {
			t.Fatalf("ManageSync timeout took %s; want <800ms", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("listenAndServeTLSWithManager never returned")
	}

	if bm.started.Load() == 0 {
		t.Fatal("blockingManager.ManageSync was never invoked")
	}
}

// TestPollPool_SeedsSynchronously is the regression for Bug 2.2: without
// the fix, the pool cache stays empty until the first ticker tick
// (2s), so requests that land in that window surface as 502s. With the
// fix, the cache is populated before PollPool begins iterating.
func TestPollPool_SeedsSynchronously(t *testing.T) {
	t.Parallel()

	// Stand up a fake /backends handler on a unix socket. The handler
	// returns one alive backend; the test asserts that by the time
	// PollPool reaches its ticker loop (well under pollInterval) the
	// server's pool cache already contains that backend.
	sockPath := filepath.Join(t.TempDir(), "pool.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var served atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/backends", func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		backends := []shared.BackendInfo{
			{Port: 9050, Alive: true, Backend: "seed.onion"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(backends)
	})
	httpSrv := &http.Server{Handler: mux}
	go func() { _ = httpSrv.Serve(ln) }()
	t.Cleanup(func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
	})

	// Minimal proxy.Server: PollPool only needs cfg to satisfy the
	// type shape and the pool-cache mutex. We do not exercise any
	// middleware in this test.
	s := &Server{cfg: &config.Config{}}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.PollPool(ctx, sockPath)
	}()

	// Wait for the synchronous first fetch. Without the fix the pool
	// stays empty until the first tick (2s); with the fix populated
	// well under 500ms.
	deadline := time.Now().Add(1 * time.Second)
	var got []shared.BackendInfo
	for time.Now().Before(deadline) {
		got = s.getPool()
		if len(got) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(got) == 0 {
		cancel()
		<-done
		t.Fatalf("pool cache still empty after 1s; synchronous seeding failed (served=%d)", served.Load())
	}
	if got[0].Backend != "seed.onion" {
		t.Fatalf("pool[0].Backend = %q, want seed.onion", got[0].Backend)
	}
	// Extra belt-and-braces: the fetch should land before pollInterval
	// (2s) would have fired. We already asserted <1s, so just reuse
	// that observation and cancel.
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("PollPool did not exit within 2s of ctx cancel")
	}
}
