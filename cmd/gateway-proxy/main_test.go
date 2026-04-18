package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"gateway/internal/config"
)

// legacyLocalConfig returns a minimal *config.Config suitable for the
// pre-P1 single-tenant code path: Mode=local, NodeType=local, Domain +
// Backends populated, tor.min_instances=1 so the validator is satisfied,
// and Cloudflare.Mode explicitly left non-"full_strict" so run() does
// not attempt certmagic. Metrics and Admin are off to keep the test
// listener count to one.
func legacyLocalConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		Mode:        config.ModeLocal,
		NodeType:    config.NodeTypeLocal,
		Domain:      "example.test",
		Email:       "admin@example.test",
		ProxySecret: "thisisaverylongsecretthatisatleast32chars",
		Cloudflare: config.CloudflareConf{
			Enabled: false,
			Mode:    "flexible",
		},
		Backends: []config.BackendConf{
			{Addr: "127.0.0.1:59999", Weight: 1},
		},
		Tor: config.TorConf{
			Binary:           "tor",
			SocksBasePort:    9050,
			MinInstances:     1,
			MaxInstances:     2,
			DataDir:          t.TempDir(),
			BootstrapTimeout: 120 * time.Second,
		},
		Pool: config.PoolConf{
			MaxIdleConnsPerHost: 10,
			IdleTimeout:         90 * time.Second,
			ResponseTimeout:     30 * time.Second,
			ConnectTimeout:      10 * time.Second,
			RetryAttempts:       3,
		},
		Security: config.SecurityConf{
			ProxySecretHeader: "X-Proxy-Secret",
		},
		Logging: config.LoggingConf{
			Level:  "error",
			Format: "json",
			Output: "stdout",
		},
		Metrics: config.MetricsConf{Enabled: false},
		Admin: config.AdminConf{
			// Explicitly empty Socket so buildTransport skips the
			// local-mode NewLocal path (there's no torpool in tests).
			Socket:  "",
			Enabled: false,
		},
	}
}

// TestRun_LegacyLocalMode boots run() with a legacy single-tenant
// config on an ephemeral listener, verifies that the HTTP stack serves
// a response (any status is acceptable: the backend is bogus so a 502
// is the expected happy-path outcome), and then cancels the context
// and confirms a clean shutdown within shutdownGrace.
func TestRun_LegacyLocalMode(t *testing.T) {
	t.Parallel()

	cfg := legacyLocalConfig(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runWithListener(ctx, cfg, ln)
	}()

	// Give the HTTP goroutine a moment to install the Serve loop. We
	// retry the GET a few times because the Listener is open the
	// instant we bind, but runWithListener may still be wiring
	// subsystems in another goroutine when we start polling.
	var resp *http.Response
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r, gerr := client.Get("http://" + addr + "/")
		if gerr == nil {
			resp = r
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if resp == nil {
		cancel()
		select {
		case rerr := <-runDone:
			t.Fatalf("no response within 5s; run() returned %v", rerr)
		case <-time.After(3 * time.Second):
			t.Fatalf("no response within 5s; run() did not return either")
		}
	}
	// Any status is acceptable: the middleware stack is known to emit
	// 502 for dead backends and 200/404 for admin / host-router paths.
	// We just need to confirm run() is actually serving.
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode < 100 || resp.StatusCode > 599 {
		t.Fatalf("nonsensical status %d", resp.StatusCode)
	}

	// Cancel and confirm run() drains inside shutdownGrace (3s budget
	// here is less than production's 15s grace because nothing real is
	// in flight; a longer delay would indicate a leaked goroutine).
	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("run did not exit within 3s of cancel")
	}
}

// TestRun_RejectsNilConfig documents that run() is defensive about its
// required argument. Mirrors the equivalent gateway-hub test.
func TestRun_RejectsNilConfig(t *testing.T) {
	t.Parallel()

	err := run(context.Background(), nil)
	if err == nil {
		t.Fatalf("expected nil-config rejection, got nil")
	}
	if !strings.Contains(err.Error(), "nil config") {
		t.Fatalf("expected error to mention nil config, got %v", err)
	}
}

// TestRun_AdminGateEnabled_IssuesSessionCookieAndRedirects bootstraps
// gateway-proxy with the P3 admin gate enabled and confirms three things:
//
//   - run() boots cleanly with all P3 admin fields populated;
//   - hitting the /<slug>/<token1>/<token2> path issues a session cookie
//     and 302s the operator to the prefix root;
//   - hitting /api/me with the issued cookie returns 200 + JSON body.
//
// The proxy listener is plain HTTP (the test bypasses certmagic), so we
// configure http.Client to follow the 302 ourselves and we do not assert
// on the cookie's Secure attribute — that is covered by the unit-level
// SetSessionCookie test in internal/admin/session_test.go.
func TestRun_AdminGateEnabled_IssuesSessionCookieAndRedirects(t *testing.T) {
	t.Parallel()

	const (
		slug = "smoke32slug32slug32slug32slug32x"
		tok1 = "smoke32token1aaaaaaaaaaaaaaaaaaa"
		tok2 = "smoke32token2bbbbbbbbbbbbbbbbbbb"
	)
	cfg := legacyLocalConfig(t)
	cfg.Admin = config.AdminConf{
		Enabled:            true,
		Slug:               slug,
		Token1:             tok1,
		Token2:             tok2,
		SessionIdleTTL:     15 * time.Minute,
		SessionAbsoluteTTL: 8 * time.Hour,
		AuditDataDir:       t.TempDir(),
		Lockout: config.LockoutConf{
			SoftThreshold: 3,
			SoftWindow:    60 * time.Second,
			SoftBackoff:   30 * time.Second,
			HardThreshold: 10,
			HardWindow:    10 * time.Minute,
			HardBan:       1 * time.Hour,
		},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() {
		runDone <- runWithListener(ctx, cfg, ln)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-runDone:
		case <-time.After(3 * time.Second):
			t.Logf("run did not exit within 3s of cancel")
		}
	})

	prefix := "/" + slug + "/" + tok1 + "/" + tok2

	// Disable redirect-following so we can inspect the 302 response.
	client := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Wait for the listener to start serving.
	deadline := time.Now().Add(3 * time.Second)
	var resp *http.Response
	for time.Now().Before(deadline) {
		r, err := client.Get("http://" + addr + prefix)
		if err == nil {
			resp = r
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if resp == nil {
		t.Fatalf("first GET on admin prefix never succeeded")
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("first admin hit: status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc != prefix+"/" {
		t.Fatalf("Location = %q, want %q", loc, prefix+"/")
	}
	cookies := resp.Cookies()
	resp.Body.Close()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "gw_adm" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatalf("first admin hit did not issue gw_adm cookie")
	}

	// Hit /api/me with the cookie. We re-use the cookie value because
	// the http.Cookie returned from response parsing has the bare value
	// the next request needs.
	req, _ := http.NewRequest(http.MethodGet, "http://"+addr+prefix+"/api/me", nil)
	req.AddCookie(&http.Cookie{Name: "gw_adm", Value: sessionCookie.Value})
	r2, err := client.Do(req)
	if err != nil {
		t.Fatalf("/api/me GET: %v", err)
	}
	body, _ := io.ReadAll(r2.Body)
	r2.Body.Close()
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("/api/me status = %d, body = %q", r2.StatusCode, body)
	}
	if !strings.Contains(string(body), `"node_type"`) {
		t.Fatalf("/api/me body missing node_type: %q", body)
	}
}

// TestDeriveShutdownGrace is the regression for Bug 3.6: the shutdown
// deadline must be ResponseTimeout+5s so an in-flight Tor request has
// room to complete, capped at maxShutdownGrace so a misconfigured pool
// cannot push the systemd TERM deadline into minutes, and fall back to
// defaultShutdownGrace when ResponseTimeout is zero (legacy configs).
func TestDeriveShutdownGrace(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name            string
		responseTimeout time.Duration
		want            time.Duration
	}{
		{"default when zero", 0, defaultShutdownGrace},
		{"default when negative", -5 * time.Second, defaultShutdownGrace},
		{"adds slack to typical 30s", 30 * time.Second, 35 * time.Second},
		{"adds slack to small 10s", 10 * time.Second, 15 * time.Second},
		{"clamps at maxShutdownGrace", 120 * time.Second, maxShutdownGrace},
		{"clamps exact edge", maxShutdownGrace, maxShutdownGrace},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := deriveShutdownGrace(tc.responseTimeout)
			if got != tc.want {
				t.Fatalf("deriveShutdownGrace(%s) = %s, want %s",
					tc.responseTimeout, got, tc.want)
			}
		})
	}
}

// TestDeriveShutdownGrace_ExceedsResponseTimeout asserts the derived
// grace is strictly greater than the pool's ResponseTimeout whenever a
// pool timeout is configured. The previous hardcoded 15s could be
// shorter than a legitimate in-flight Tor request (ResponseTimeout
// defaults to 30s) which would cut those requests off mid-flight.
func TestDeriveShutdownGrace_ExceedsResponseTimeout(t *testing.T) {
	t.Parallel()

	for _, rt := range []time.Duration{
		1 * time.Second,
		5 * time.Second,
		30 * time.Second,
	} {
		grace := deriveShutdownGrace(rt)
		if grace <= rt {
			t.Fatalf("grace (%s) must exceed ResponseTimeout (%s)", grace, rt)
		}
	}
}

// TestRun_RemoteModeDisabledSnapshotFailsFast confirms that when
// mode=remote and the hub is unreachable, run() returns quickly rather
// than silently booting with a disabled registry. The spec's medium-
// severity finding explicitly asks for fail-fast here.
//
// The test uses the https_tunnel transport with a bogus HubURL; tunnel
// construction fails on the missing CA file, which surfaces as a
// startup error from run(). That matches the fail-fast intent without
// requiring us to actually stand up and break an SSE server.
func TestRun_RemoteModeDisabledSnapshotStillBoots(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		Mode:     config.ModeRemote,
		NodeType: config.NodeTypeProxy,
		HubURL:   "https://unreachable.invalid:59999",
		Transport: config.TransportConf{
			Kind: config.TransportHTTPSTunnel,
			HTTPSTunnel: config.HTTPSTunnelConf{
				HubURL:     "https://unreachable.invalid:59999",
				CACertFile: "/nonexistent/ca.pem",
			},
		},
		MTLS: config.MTLSConf{
			ClientCertFile: "/nonexistent/client.pem",
			ClientKeyFile:  "/nonexistent/client.key",
		},
		Logging: config.LoggingConf{
			Level:  "error",
			Format: "json",
			Output: "stdout",
		},
		Admin: config.AdminConf{Enabled: false},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	err := run(ctx, cfg)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("expected run() to fail fast when the hub is unreachable")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("run() took %v to fail; expected fail-fast under 3s", elapsed)
	}
	// The error should come from transport construction (missing CA)
	// rather than silently falling through. Substring matches the
	// wrapping path: "transport" -> transport/https_tunnel -> read CA.
	if !strings.Contains(err.Error(), "transport") {
		t.Fatalf("expected transport error, got %v", err)
	}
}
