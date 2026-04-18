package blocklist

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gateway/internal/feature"
	"gateway/internal/shared"
)

// hijackableRecorder wraps httptest.ResponseRecorder with a net.Conn pair
// so handlers can call Hijack and close the connection. Tests inspect the
// closed flag to confirm drop behaviour.
type hijackableRecorder struct {
	*httptest.ResponseRecorder
	server     net.Conn
	client     net.Conn
	rw         *bufio.ReadWriter
	hijacked   atomic.Bool
	closed     atomic.Bool
	disallowHJ bool
	hijackErr  error
}

func newHijackable() *hijackableRecorder {
	s, c := net.Pipe()
	return &hijackableRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		server:           s,
		client:           c,
		rw:               bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s)),
	}
}

func (h *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h.disallowHJ {
		return nil, nil, http.ErrNotSupported
	}
	if h.hijackErr != nil {
		return nil, nil, h.hijackErr
	}
	h.hijacked.Store(true)
	// Wrap server conn so Close sets our flag.
	return &closeTrackingConn{Conn: h.server, closed: &h.closed}, h.rw, nil
}

type closeTrackingConn struct {
	net.Conn
	closed *atomic.Bool
}

func (c *closeTrackingConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

// helper: build a resolver-backed middleware with a fresh registry that
// runs Observe with the supplied globals/tenants.
func build(t *testing.T, globals feature.GlobalsSnapshot, tenants map[string]feature.TenantSnapshot) (*Feature, http.Handler) {
	t.Helper()
	reg := feature.NewRegistry()
	f := RegisterWith(reg)
	if err := reg.Reload(globals, tenants); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "OK")
	})
	return f, reg.BuildChain(inner)
}

// patternSnapshot constructs a FeatureSnapshot with the supplied list of
// pattern/action pairs and an optional default_action.
func patternSnapshot(enabled bool, def string, patterns ...map[string]any) shared.FeatureSnapshot {
	params := map[string]any{}
	if def != "" {
		params["default_action"] = def
	}
	if len(patterns) > 0 {
		raw := make([]any, len(patterns))
		for i, p := range patterns {
			raw[i] = p
		}
		params["patterns"] = raw
	}
	return shared.FeatureSnapshot{Enabled: enabled, Params: params, Version: 1}
}

func TestValidateRejectsBadRegex(t *testing.T) {
	f := New()
	snap := patternSnapshot(true, "drop", map[string]any{
		"pattern": "(unterminated",
		"action":  "404",
	})
	if err := f.Validate(snap); err == nil {
		t.Fatalf("expected validate error for bad regex")
	}
}

func TestValidateRejectsInvalidAction(t *testing.T) {
	f := New()
	snap := patternSnapshot(true, "", map[string]any{
		"pattern": "ok",
		"action":  "kaboom",
	})
	if err := f.Validate(snap); err == nil {
		t.Fatalf("expected validate error for invalid action")
	}
}

func TestValidateRejectsMissingActionWithoutDefault(t *testing.T) {
	f := New()
	snap := patternSnapshot(true, "", map[string]any{
		"pattern": "ok",
	})
	err := f.Validate(snap)
	if err == nil {
		t.Fatalf("expected validate error for missing action without default")
	}
	if !strings.Contains(err.Error(), "action") {
		t.Errorf("expected error to mention action, got %v", err)
	}
}

func TestValidateAcceptsMissingActionWithDefault(t *testing.T) {
	f := New()
	snap := patternSnapshot(true, "drop", map[string]any{
		"pattern": "ok",
	})
	if err := f.Validate(snap); err != nil {
		t.Fatalf("expected validate to succeed, got %v", err)
	}
}

func TestValidateRejectsMissingPattern(t *testing.T) {
	f := New()
	snap := patternSnapshot(true, "drop", map[string]any{
		"action": "404",
	})
	if err := f.Validate(snap); err == nil {
		t.Fatalf("expected validate error for missing pattern")
	}
}

func TestValidateAllowsDisabledEmptySnapshot(t *testing.T) {
	f := New()
	if err := f.Validate(shared.FeatureSnapshot{}); err != nil {
		t.Fatalf("expected validate to accept disabled empty snapshot, got %v", err)
	}
}

func TestMiddlewarePassThroughWhenGloballyDisabled(t *testing.T) {
	globals := feature.GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: patternSnapshot(false, "drop", map[string]any{
				"pattern": "/blocked",
				"action":  "404",
			}),
		},
	}
	_, chain := build(t, globals, nil)

	req := httptest.NewRequest(http.MethodGet, "http://example.tld/blocked", nil)
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 when disabled, got %d", rec.Code)
	}
}

func TestMiddlewarePassThroughWhenNoMatch(t *testing.T) {
	globals := feature.GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: patternSnapshot(true, "drop", map[string]any{
				"pattern": "^/never$",
				"action":  "404",
			}),
		},
	}
	_, chain := build(t, globals, nil)

	req := httptest.NewRequest(http.MethodGet, "http://example.tld/something-else", nil)
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 when no match, got %d", rec.Code)
	}
}

func TestMiddleware404Action(t *testing.T) {
	globals := feature.GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: patternSnapshot(true, "", map[string]any{
				"pattern": "(?i)wp-login",
				"action":  "404",
			}),
		},
	}
	_, chain := build(t, globals, nil)

	req := httptest.NewRequest(http.MethodGet, "http://example.tld/WP-Login.php", nil)
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("expected empty body, got %q", rec.Body.String())
	}
}

func TestMiddleware429Action(t *testing.T) {
	globals := feature.GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: patternSnapshot(true, "", map[string]any{
				"pattern": `^/api/.*$`,
				"action":  "429",
			}),
		},
	}
	_, chain := build(t, globals, nil)

	req := httptest.NewRequest(http.MethodGet, "http://example.tld/api/burst", nil)
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec.Code)
	}
}

func TestMiddlewareDropHijacksConnection(t *testing.T) {
	globals := feature.GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: patternSnapshot(true, "", map[string]any{
				"pattern": `\.env$`,
				"action":  "drop",
			}),
		},
	}
	_, chain := build(t, globals, nil)

	req := httptest.NewRequest(http.MethodGet, "http://example.tld/.env", nil)
	rec := newHijackable()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// The client side would normally read the response. For drop
		// the connection is closed; reads return EOF. Drain anything.
		_, _ = io.ReadAll(rec.client)
	}()

	chain.ServeHTTP(rec, req)
	_ = rec.client.Close()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("client-side read did not return after drop")
	}

	if !rec.hijacked.Load() {
		t.Fatalf("expected connection to be hijacked on drop")
	}
	if !rec.closed.Load() {
		t.Fatalf("expected hijacked connection to be closed on drop")
	}
}

func TestMiddlewareDropFallsBackTo400WhenNotHijackable(t *testing.T) {
	globals := feature.GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: patternSnapshot(true, "", map[string]any{
				"pattern": "^/nope$",
				"action":  "drop",
			}),
		},
	}
	_, chain := build(t, globals, nil)

	req := httptest.NewRequest(http.MethodGet, "http://example.tld/nope", nil)
	rec := httptest.NewRecorder() // not a Hijacker
	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected fallback 400, got %d", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("expected empty body, got %q", rec.Body.String())
	}
}

func TestMiddlewareTimeoutActionSleepsThenCloses(t *testing.T) {
	// Use a tiny timeout so the test is fast.
	globals := feature.GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: {
				Enabled: true,
				Params: map[string]any{
					"timeout_seconds": 0, // falls back to small override below
					"patterns": []any{
						map[string]any{
							"pattern": `^/slow`,
							"action":  "timeout",
						},
					},
				},
				Version: 1,
			},
		},
	}
	f, chain := build(t, globals, nil)
	// Override the compiled timeout so the test finishes in reasonable
	// time — we inspect what Observe stored.
	p := f.compiled.Load()
	if p == nil {
		t.Fatalf("no compiled ruleset")
	}
	rules := (*p)[globalTenantKey]
	if rules == nil {
		t.Fatalf("no global rules installed")
	}
	rules.timeout = 40 * time.Millisecond

	req := httptest.NewRequest(http.MethodGet, "http://example.tld/slow", nil)
	rec := newHijackable()

	start := time.Now()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.ReadAll(rec.client)
	}()
	chain.ServeHTTP(rec, req)
	_ = rec.client.Close()
	elapsed := time.Since(start)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("timeout action did not complete")
	}

	if elapsed < 30*time.Millisecond {
		t.Errorf("timeout action completed too fast: %v", elapsed)
	}
	if !rec.hijacked.Load() {
		t.Fatalf("expected connection to be hijacked after timeout")
	}
	if !rec.closed.Load() {
		t.Fatalf("expected connection to be closed after timeout")
	}
}

func TestMiddlewareTimeoutRespectsRequestCancellation(t *testing.T) {
	// A very long timeout value — test cancels the request context so the
	// handler must return promptly.
	globals := feature.GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: {
				Enabled: true,
				Params: map[string]any{
					"timeout_seconds": 30,
					"patterns": []any{
						map[string]any{
							"pattern": "/anything",
							"action":  "timeout",
						},
					},
				},
				Version: 1,
			},
		},
	}
	_, chain := build(t, globals, nil)

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "http://example.tld/anything", nil)
	rec := newHijackable()

	done := make(chan struct{})
	go func() {
		defer close(done)
		chain.ServeHTTP(rec, req)
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("timeout action did not observe request cancellation")
	}
}

func TestMiddlewareTenantOverridesGlobal(t *testing.T) {
	globals := feature.GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: patternSnapshot(true, "drop", map[string]any{
				"pattern": "^/global-block$",
				"action":  "404",
			}),
		},
	}
	tenantSnap := patternSnapshot(true, "", map[string]any{
		"pattern": "^/tenant-only$",
		"action":  "429",
	})
	tenants := map[string]feature.TenantSnapshot{
		"tenant-a.tld": {
			Host:    "tenant-a.tld",
			Enabled: true,
			Features: map[string]shared.FeatureSnapshot{
				FeatureName: tenantSnap,
			},
		},
	}
	_, chain := build(t, globals, tenants)

	// Request with tenant-a context — should hit tenant rules, not global.
	req := httptest.NewRequest(http.MethodGet, "http://tenant-a.tld/tenant-only", nil)
	req = req.WithContext(feature.WithTenant(req.Context(), &feature.TenantSnapshot{
		Host:    "tenant-a.tld",
		Enabled: true,
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: tenantSnap,
		},
	}))
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected tenant-specific 429, got %d", rec.Code)
	}

	// Path that global matches but tenant does not — should pass through
	// because tenant override replaces (not merges) globals.
	req2 := httptest.NewRequest(http.MethodGet, "http://tenant-a.tld/global-block", nil)
	req2 = req2.WithContext(feature.WithTenant(req2.Context(), &feature.TenantSnapshot{
		Host:    "tenant-a.tld",
		Enabled: true,
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: tenantSnap,
		},
	}))
	rec2 := httptest.NewRecorder()
	chain.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected tenant override to isolate from globals (200), got %d", rec2.Code)
	}

	// Request without tenant context — should use globals and get 404.
	req3 := httptest.NewRequest(http.MethodGet, "http://other.tld/global-block", nil)
	rec3 := httptest.NewRecorder()
	chain.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusNotFound {
		t.Fatalf("expected globals 404 for non-tenant request, got %d", rec3.Code)
	}
}

func TestMiddlewareFirstMatchWins(t *testing.T) {
	globals := feature.GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: patternSnapshot(true, "",
				map[string]any{"pattern": `^/api/`, "action": "429"},
				map[string]any{"pattern": `^/api/secret$`, "action": "404"},
			),
		},
	}
	_, chain := build(t, globals, nil)

	req := httptest.NewRequest(http.MethodGet, "http://example.tld/api/secret", nil)
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected first-match 429, got %d", rec.Code)
	}
}

func TestMiddlewareDefaultActionAppliesWhenPatternHasNone(t *testing.T) {
	globals := feature.GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: patternSnapshot(true, "404",
				map[string]any{"pattern": `^/default-only$`},
			),
		},
	}
	_, chain := build(t, globals, nil)

	req := httptest.NewRequest(http.MethodGet, "http://example.tld/default-only", nil)
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected default-action 404, got %d", rec.Code)
	}
}

func TestRegisterWithInstallsObserver(t *testing.T) {
	reg := feature.NewRegistry()
	f := RegisterWith(reg)

	// Observe initial empty state.
	if f.enabled.Load() {
		t.Fatalf("expected disabled at construction")
	}

	globals := feature.GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: patternSnapshot(true, "drop",
				map[string]any{"pattern": "^/x$", "action": "404"},
			),
		},
	}
	if err := reg.Reload(globals, nil); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if !f.enabled.Load() {
		t.Fatalf("expected enabled after Reload with enabled globals")
	}

	// Reload with disabled globals — enabled flag clears.
	if err := reg.Reload(feature.GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: {Enabled: false},
		},
	}, nil); err != nil {
		t.Fatalf("second Reload: %v", err)
	}
	if f.enabled.Load() {
		t.Fatalf("expected disabled after Reload with disabled globals")
	}
}

func TestRegisterWithRejectsInvalidSnapshot(t *testing.T) {
	reg := feature.NewRegistry()
	RegisterWith(reg)

	err := reg.Reload(feature.GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: patternSnapshot(true, "drop",
				map[string]any{"pattern": "(unterminated"},
			),
		},
	}, nil)
	if err == nil {
		t.Fatalf("expected Reload to fail on bad regex")
	}
}

func TestObserveEnabledFlagConsidersTenants(t *testing.T) {
	reg := feature.NewRegistry()
	f := RegisterWith(reg)

	globals := feature.GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: {Enabled: false},
		},
	}
	tenants := map[string]feature.TenantSnapshot{
		"t.tld": {
			Host:    "t.tld",
			Enabled: true,
			Features: map[string]shared.FeatureSnapshot{
				FeatureName: patternSnapshot(true, "",
					map[string]any{"pattern": "^/z$", "action": "404"},
				),
			},
		},
	}
	if err := reg.Reload(globals, tenants); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if !f.enabled.Load() {
		t.Fatalf("expected enabled flag to be set when any tenant has enabled override")
	}
}

func TestConcurrentRequestsAndReloadsAreSafe(t *testing.T) {
	reg := feature.NewRegistry()
	f := RegisterWith(reg)

	// Seed with a meaningful ruleset so hot path exercises matching.
	seed := feature.GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: patternSnapshot(true, "drop",
				map[string]any{"pattern": `^/blocked/.*`, "action": "404"},
				map[string]any{"pattern": `^/slow$`, "action": "429"},
			),
		},
	}
	if err := reg.Reload(seed, nil); err != nil {
		t.Fatalf("seed Reload: %v", err)
	}

	chain := reg.BuildChain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	const reqGoroutines = 100
	const reloadGoroutines = 10
	const duration = 500 * time.Millisecond

	var (
		wg          sync.WaitGroup
		reqCount    atomic.Int64
		reloadCount atomic.Int64
		anomaly     atomic.Int64
		stop        atomic.Bool
	)

	tenantCtx := feature.WithTenant(context.Background(), &feature.TenantSnapshot{
		Host:    "example.tld",
		Enabled: true,
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: patternSnapshot(true, "429",
				map[string]any{"pattern": `^/tenant-block$`},
			),
		},
	})

	// Request goroutines.
	for i := 0; i < reqGoroutines; i++ {
		wg.Add(1)
		gi := i
		go func() {
			defer wg.Done()
			paths := []string{"/harmless", "/blocked/xyz", "/slow", "/tenant-block"}
			for !stop.Load() {
				p := paths[gi%len(paths)]
				req := httptest.NewRequest(http.MethodGet, "http://example.tld"+p, nil)
				req = req.WithContext(tenantCtx)
				rec := httptest.NewRecorder()
				func() {
					defer func() {
						if r := recover(); r != nil {
							anomaly.Add(1)
						}
					}()
					chain.ServeHTTP(rec, req)
				}()
				switch rec.Code {
				case http.StatusOK, http.StatusNotFound, http.StatusTooManyRequests, http.StatusBadRequest:
					// all expected states — bad request is the
					// hijack fallback for httptest.ResponseRecorder.
				default:
					anomaly.Add(1)
				}
				reqCount.Add(1)
			}
		}()
	}

	// Reload goroutines.
	for i := 0; i < reloadGoroutines; i++ {
		wg.Add(1)
		gi := i
		go func() {
			defer wg.Done()
			variants := []feature.GlobalsSnapshot{
				seed,
				{Features: map[string]shared.FeatureSnapshot{FeatureName: {Enabled: false}}},
				{Features: map[string]shared.FeatureSnapshot{FeatureName: patternSnapshot(true, "drop",
					map[string]any{"pattern": `^/x/`, "action": "404"},
				)}},
				{Features: map[string]shared.FeatureSnapshot{FeatureName: patternSnapshot(true, "",
					map[string]any{"pattern": `^/other$`, "action": "429"},
				)}},
			}
			tenants := map[string]feature.TenantSnapshot{
				"example.tld": {
					Host:    "example.tld",
					Enabled: true,
					Features: map[string]shared.FeatureSnapshot{
						FeatureName: patternSnapshot(true, "429",
							map[string]any{"pattern": `^/tenant-block$`},
						),
					},
				},
			}
			k := 0
			for !stop.Load() {
				g := variants[(gi+k)%len(variants)]
				if err := reg.Reload(g, tenants); err != nil {
					anomaly.Add(1)
				}
				reloadCount.Add(1)
				k++
			}
		}()
	}

	time.Sleep(duration)
	stop.Store(true)
	wg.Wait()

	if anomaly.Load() != 0 {
		t.Fatalf("observed %d anomalies during concurrent test", anomaly.Load())
	}
	if reqCount.Load() == 0 {
		t.Fatalf("no requests processed")
	}
	if reloadCount.Load() == 0 {
		t.Fatalf("no reloads processed")
	}
	// Feature pointer should still be accessible and compiled slot non-nil.
	if p := f.compiled.Load(); p == nil {
		t.Fatalf("compiled ruleset lost after concurrent test")
	}
}

func TestParseRulesAcceptsAltSliceShape(t *testing.T) {
	// Some config loaders normalise sequences into []map[string]any
	// instead of []any. parseRules must accept both.
	cfg := shared.FeatureSnapshot{
		Enabled: true,
		Params: map[string]any{
			"default_action": "drop",
			"patterns": []map[string]any{
				{"pattern": "^/a$", "action": "404"},
			},
		},
	}
	parsed, def, _, err := parseRules(cfg)
	if err != nil {
		t.Fatalf("parseRules: %v", err)
	}
	if def != shared.BlockActionDrop {
		t.Errorf("default action: got %q, want drop", def)
	}
	if len(parsed) != 1 {
		t.Fatalf("parsed count = %d, want 1", len(parsed))
	}
	if parsed[0].pattern != "^/a$" {
		t.Errorf("pattern: got %q", parsed[0].pattern)
	}
}

func TestParseRulesRejectsWrongShape(t *testing.T) {
	cfg := shared.FeatureSnapshot{
		Enabled: true,
		Params: map[string]any{
			"patterns": "not-a-list",
		},
	}
	if _, _, _, err := parseRules(cfg); err == nil {
		t.Fatalf("expected error for non-list patterns field")
	}
}

func TestValidateSurfacesJoinedErrors(t *testing.T) {
	// Indirect test: use a registry reload with a bad snapshot — the
	// registry joins feature errors, but we just want blocklist to
	// surface a regex error verbatim.
	f := New()
	err := f.Validate(patternSnapshot(true, "drop", map[string]any{
		"pattern": "[bad",
		"action":  "404",
	}))
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "[bad") {
		t.Errorf("expected error to mention the offending pattern, got %v", err)
	}
	// errors.Is should not crash on regexp's unwrap chain.
	_ = errors.Is(err, fmt.Errorf("sentinel"))
}

func TestHijackErrorFallsBackTo400(t *testing.T) {
	globals := feature.GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: patternSnapshot(true, "", map[string]any{
				"pattern": "^/x$",
				"action":  "drop",
			}),
		},
	}
	_, chain := build(t, globals, nil)

	req := httptest.NewRequest(http.MethodGet, "http://example.tld/x", nil)
	rec := newHijackable()
	rec.hijackErr = errors.New("forced")

	chain.ServeHTTP(rec, req)

	// The underlying recorder got the 400 fallback.
	if rec.ResponseRecorder.Code != http.StatusBadRequest {
		t.Fatalf("expected hijack-failure fallback 400, got %d", rec.ResponseRecorder.Code)
	}
}
