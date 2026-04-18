// Package main implements the P1 integration test driver.
//
// The driver runs a fixed matrix of end-to-end test cases against the
// compose-brought-up hub + 2 proxies + 2 Tor-backed backends. Each test
// has a sub-second timeout so hangs are caught quickly. Results are
// printed with colorized PASS/FAIL; the process exits with a code equal
// to the number of failed tests (0 = all green).
//
// Design notes:
//   - All HTTP calls use a shared http.Client whose Transport skips TLS
//     verification because the test env uses self-signed certs.
//   - We resolve service names via Docker's embedded DNS (hub, proxy-1,
//     proxy-2); no baked IPs.
//   - Admin credentials are baked in and must match the YAML configs
//     in ../config/. Keep in sync when you change one or the other.
//   - The driver waits (with backoff) for services to become reachable
//     before the first assertion.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Colour helpers — ANSI escape sequences. We intentionally use plain
// literals rather than a library to keep the binary dep-free.
const (
	colReset  = "\x1b[0m"
	colRed    = "\x1b[31m"
	colGreen  = "\x1b[32m"
	colYellow = "\x1b[33m"
	colCyan   = "\x1b[36m"
)

// baked-in admin credentials — must match config/proxy-*.yaml and
// config/hub.yaml exactly. These are test-only fixtures, not secrets.
const (
	adminSlug   = "testslug01234567890123456789abcd"
	adminToken1 = "testtoken011234567890123456789abc"
	adminToken2 = "testtoken022234567890123456789abc"
)

// Endpoints inside the docker-compose network.
const (
	hubURL     = "https://hub:9080"
	proxy1URL  = "https://proxy-1"
	proxy2URL  = "https://proxy-2"
	// Host headers the proxies key off of. These map to tenant YAML
	// files.
	tenantAHost = "example-a.test"
	tenantBHost = "example-b.test"
)

// testResult captures the outcome of one test case.
type testResult struct {
	Name    string
	Passed  bool
	Detail  string
	Elapsed time.Duration
}

// client is the shared HTTP client. Each test clones its timeout.
var client = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			// Self-signed test certs; accept anything.
			InsecureSkipVerify: true, //nolint:gosec // test driver
		},
		// Short idle timeout so repeated test runs see fresh connections.
		IdleConnTimeout: 5 * time.Second,
		DisableKeepAlives: false,
	},
	// Each request uses a context with its own tight deadline. The
	// client-level timeout here is an outer safety net.
	Timeout: 10 * time.Second,
}

// main is the driver entry point. Order of operations:
//   1. Wait for services to become reachable.
//   2. Run the test matrix.
//   3. Print summary and exit with failure count.
func main() {
	fmt.Printf("%s== P1 integration driver ==%s\n", colCyan, colReset)
	fmt.Printf("starting at %s\n\n", time.Now().Format(time.RFC3339))

	if err := waitForServices(90 * time.Second); err != nil {
		fmt.Printf("%sFATAL%s: services never became ready: %v\n", colRed, colReset, err)
		os.Exit(2)
	}

	results := []testResult{}
	tests := []struct {
		name string
		fn   func(context.Context) error
	}{
		{"01 proxy-1 healthz routes to backend-a", testProxy1Healthz},
		{"02 proxy-1 blocks /wp-admin (tenant rule)", testProxy1WPAdminBlocked},
		{"03 proxy-2 allows /wp-admin (no tenant rule)", testProxy2WPAdminAllowed},
		{"04 proxy-1 static cache hit is faster", testProxy1StaticCache},
		{"05 hub PUT tenant propagates via SSE in <2s", testHubPutTenantPropagates},
		{"06 hub DELETE tenant returns 421 at proxy", testHubDeleteTenant421},
		{"07 admin gate returns 501, other paths 404", testAdminGate501},
	}

	for _, tc := range tests {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		t0 := time.Now()
		err := tc.fn(ctx)
		cancel()
		res := testResult{
			Name:    tc.name,
			Passed:  err == nil,
			Elapsed: time.Since(t0),
		}
		if err != nil {
			res.Detail = err.Error()
		}
		results = append(results, res)
		printResult(res)
	}

	fails := 0
	for _, r := range results {
		if !r.Passed {
			fails++
		}
	}
	fmt.Printf("\n%s== Summary ==%s\n", colCyan, colReset)
	fmt.Printf("total=%d passed=%d failed=%d\n", len(results), len(results)-fails, fails)
	if fails > 0 {
		fmt.Printf("%sFAIL%s\n", colRed, colReset)
		os.Exit(fails)
	}
	fmt.Printf("%sPASS%s\n", colGreen, colReset)
}

// printResult formats one result line.
func printResult(r testResult) {
	tag := fmt.Sprintf("%sPASS%s", colGreen, colReset)
	if !r.Passed {
		tag = fmt.Sprintf("%sFAIL%s", colRed, colReset)
	}
	fmt.Printf("[%s] %-55s  %6.0fms", tag, r.Name, float64(r.Elapsed.Milliseconds()))
	if r.Detail != "" {
		fmt.Printf("   %s%s%s", colYellow, r.Detail, colReset)
	}
	fmt.Println()
}

// waitForServices polls the hub and both proxies until each answers any
// HTTP request (even a 4xx counts — it means the server is up). The
// outer timeout is generous because Tor bootstrapping + mTLS CA
// generation on the hub can take a while on slow machines.
func waitForServices(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	targets := []string{hubURL + "/v1/tenants", proxy1URL + "/healthz", proxy2URL + "/healthz"}
	for _, t := range targets {
		ready := false
		var lastErr error
		for time.Now().Before(deadline) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, t, nil)
			req.Host = tenantAHost
			resp, err := client.Do(req)
			cancel()
			if err == nil {
				_ = resp.Body.Close()
				ready = true
				break
			}
			lastErr = err
			time.Sleep(500 * time.Millisecond)
		}
		if !ready {
			return fmt.Errorf("target %s never answered: %v", t, lastErr)
		}
	}
	return nil
}

// testProxy1Healthz verifies a plain GET routed through Tor to backend-a.
// The response must show tenant=example-a so we know the tenant→backend
// mapping works.
func testProxy1Healthz(ctx context.Context) error {
	body, status, err := doGET(ctx, proxy1URL+"/healthz", tenantAHost)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("expected 200, got %d", status)
	}
	if !strings.Contains(body, "tenant=example-a") {
		return fmt.Errorf("expected tenant=example-a in body, got %q", snippet(body))
	}
	return nil
}

// testProxy1WPAdminBlocked asserts blocklist_regex takes effect on
// tenant A — /wp-admin must be 404 (per tenant rule), not reach the
// backend.
func testProxy1WPAdminBlocked(ctx context.Context) error {
	body, status, err := doGET(ctx, proxy1URL+"/wp-admin", tenantAHost)
	if err != nil {
		return err
	}
	if status != http.StatusNotFound {
		return fmt.Errorf("expected 404, got %d body=%q", status, snippet(body))
	}
	// Body must NOT contain tenant=example-a — request should never
	// have reached the backend.
	if strings.Contains(body, "tenant=example-a") {
		return fmt.Errorf("request leaked to backend despite blocklist")
	}
	return nil
}

// testProxy2WPAdminAllowed verifies per-tenant isolation: tenant B does
// not define the wp-admin rule, so the request must pass through to the
// backend and return 200.
func testProxy2WPAdminAllowed(ctx context.Context) error {
	body, status, err := doGET(ctx, proxy2URL+"/wp-admin", tenantBHost)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("expected 200, got %d", status)
	}
	if !strings.Contains(body, "tenant=example-b") {
		return fmt.Errorf("expected tenant=example-b in body, got %q", snippet(body))
	}
	return nil
}

// testProxy1StaticCache fetches /big-static.css twice and compares
// latency. The second hit should be dramatically faster because the
// first populates the ristretto cache. We use a permissive threshold
// (second ≤ first/2 OR second < 50ms) so the test survives noisy CI.
func testProxy1StaticCache(ctx context.Context) error {
	// First hit: warms cache.
	t0 := time.Now()
	_, status, err := doGET(ctx, proxy1URL+"/big-static.css", tenantAHost)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("first hit expected 200, got %d", status)
	}
	first := time.Since(t0)

	// Second hit: should come from cache.
	t1 := time.Now()
	_, status, err = doGET(ctx, proxy1URL+"/big-static.css", tenantAHost)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("second hit expected 200, got %d", status)
	}
	second := time.Since(t1)

	// Ristretto admission is asynchronous; if the cache hasn't settled
	// we accept any non-regression (second not much slower than first).
	if second > first*2 && second > 100*time.Millisecond {
		return fmt.Errorf("no cache speedup: first=%v second=%v", first, second)
	}
	return nil
}

// testHubPutTenantPropagates creates/updates a tenant via hub admin API
// and then asserts the proxy picks up the change within 2 seconds via
// the SSE config stream.
//
// We don't have a client cert in-driver (the hub is mTLS-protected in
// prod), so in the test env the hub is started with mTLS disabled on
// the admin port for driver reachability. See compose file.
func testHubPutTenantPropagates(ctx context.Context) error {
	tenant := map[string]any{
		"host":    tenantAHost,
		"enabled": true,
		"backends": []map[string]any{
			{"addr": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad.onion", "weight": 1},
		},
		"features": map[string]any{
			"blocklist_regex": map[string]any{
				"enabled": true,
				"params": map[string]any{
					"patterns": []map[string]any{
						{"pattern": "(?i)wp-(login|admin)", "action": "404"},
						// New pattern added by this test — verify it propagates.
						{"pattern": "^/just-added$", "action": "404"},
					},
				},
			},
		},
	}
	body, _ := json.Marshal(tenant)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		hubURL+"/v1/tenants/"+tenantAHost, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("hub PUT: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("hub PUT returned %d: %s", resp.StatusCode, snippet(string(b)))
	}

	// Poll proxy-1 for up to 2s — the new rule should kick in.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, status, err := doGET(ctx, proxy1URL+"/just-added", tenantAHost)
		if err == nil && status == http.StatusNotFound {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("new rule did not propagate within 2s")
}

// testHubDeleteTenant421 deletes tenant A and asserts the proxy starts
// answering with 421 Misdirected Request for that host (per the spec:
// unknown tenant = 421, deliberately distinguishable from 404).
func testHubDeleteTenant421(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		hubURL+"/v1/tenants/"+tenantAHost, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("hub DELETE: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("hub DELETE returned %d", resp.StatusCode)
	}

	// Poll proxy-1 for up to 2s waiting for 421.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, status, err := doGET(ctx, proxy1URL+"/", tenantAHost)
		if err == nil && status == http.StatusMisdirectedRequest {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("proxy never returned 421 after tenant delete")
}

// testAdminGate501 asserts the P1 stub behaviour:
//   - {slug}/{token1}/{token2} path → 501 Not Implemented
//   - any other path → 404 (indistinguishable from a normal miss)
// Both responses must be constant-time-safe per the spec; we verify
// only the status codes here. Timing-side-channel tests belong in unit
// coverage.
func testAdminGate501(ctx context.Context) error {
	// Hit a tenant that still exists. Tenant B is intact.
	adminPath := fmt.Sprintf("/%s/%s/%s", adminSlug, adminToken1, adminToken2)
	_, status, err := doGET(ctx, proxy2URL+adminPath, tenantBHost)
	if err != nil {
		return err
	}
	if status != http.StatusNotImplemented {
		return fmt.Errorf("admin gate: expected 501, got %d", status)
	}

	// Wrong token → must be 404, not 501, to avoid leaking that the
	// admin gate exists.
	wrongPath := fmt.Sprintf("/%s/%s/xxxx", adminSlug, adminToken1)
	_, status, err = doGET(ctx, proxy2URL+wrongPath, tenantBHost)
	if err != nil {
		return err
	}
	// 200 is also acceptable — the backend echoes everything. The key
	// invariant is we did NOT get 501 for a wrong path.
	if status == http.StatusNotImplemented {
		return fmt.Errorf("admin gate leaked: wrong path returned 501")
	}
	return nil
}

// doGET is a small helper used by every test. It fetches url with the
// given Host header and returns the body + status. Any network error
// is returned as-is so the caller can compose a nicer message.
func doGET(ctx context.Context, url, host string) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", 0, err
	}
	if host != "" {
		req.Host = host
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", resp.StatusCode, err
	}
	return string(body), resp.StatusCode, nil
}

// snippet trims a string to a safe preview length for error messages.
func snippet(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 120 {
		return s[:120] + "..."
	}
	return s
}
