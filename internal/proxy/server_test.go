package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"testing"
	"time"
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
