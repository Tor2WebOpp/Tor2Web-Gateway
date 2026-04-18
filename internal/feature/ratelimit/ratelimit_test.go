package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gateway/internal/feature"
	"gateway/internal/shared"
)

// newEnabledFeature builds a Feature wired through a feature.Registry with
// the supplied globals params and tenants. The returned Feature is started
// and observes the registry; callers must t.Cleanup(f.Stop).
func newEnabledFeature(t *testing.T, globalsParams map[string]any, tenants map[string]shared.FeatureSnapshot) (*Feature, http.Handler) {
	t.Helper()
	reg := feature.NewRegistry()
	f := NewFeature()
	reg.Register(f)
	reg.AddReloadObserver(FeatureName, f.Observe)

	// Build tenant snapshots for the registry.
	tenantSnapshots := make(map[string]feature.TenantSnapshot, len(tenants))
	for host, snap := range tenants {
		tenantSnapshots[host] = feature.TenantSnapshot{
			Host:    host,
			Enabled: true,
			Features: map[string]shared.FeatureSnapshot{
				FeatureName: snap,
			},
		}
	}

	if err := reg.Reload(feature.GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: {Enabled: true, Params: globalsParams},
		},
	}, tenantSnapshots); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	f.ApplyFromSnapshots(tenantSnapshots)
	f.Start()
	t.Cleanup(f.Stop)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return f, reg.BuildChain(inner)
}

// doReq sends a single request through chain with the specified tenant
// context and client IP, then returns the recorded status.
func doReq(chain http.Handler, host, ip, path string) int {
	req := httptest.NewRequest(http.MethodGet, "http://"+host+path, nil)
	req.RemoteAddr = ip + ":12345"
	tenant := &feature.TenantSnapshot{Host: host, Enabled: true}
	req = req.WithContext(feature.WithTenant(req.Context(), tenant))
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)
	return rec.Code
}

func TestBurstAllowedBeforeRateKicksIn(t *testing.T) {
	_, chain := newEnabledFeature(t, map[string]any{
		"per_ip_rps":   1.0,
		"per_ip_burst": 5,
		"global_rps":   1000.0,
	}, map[string]shared.FeatureSnapshot{
		"tenant-a.tld": {Enabled: true, Params: map[string]any{
			"per_ip_rps":   1.0,
			"per_ip_burst": 5,
			"global_rps":   1000.0,
		}},
	})

	// Burst of 5 should succeed back-to-back.
	for i := 0; i < 5; i++ {
		if code := doReq(chain, "tenant-a.tld", "1.2.3.4", "/"); code != http.StatusOK {
			t.Fatalf("burst[%d] = %d, want 200", i, code)
		}
	}
	// 6th request should be denied.
	if code := doReq(chain, "tenant-a.tld", "1.2.3.4", "/"); code != http.StatusTooManyRequests {
		t.Fatalf("6th request = %d, want 429", code)
	}
}

func TestRPSLimitAppliedAfterBurstExhausted(t *testing.T) {
	// per_ip_rps=50, per_ip_burst=1 — first request passes, immediate
	// second is blocked, after ~25ms we should be permitted again.
	_, chain := newEnabledFeature(t, map[string]any{
		"per_ip_rps":   50.0,
		"per_ip_burst": 1,
		"global_rps":   1000.0,
	}, map[string]shared.FeatureSnapshot{
		"t.tld": {Enabled: true, Params: map[string]any{
			"per_ip_rps":   50.0,
			"per_ip_burst": 1,
			"global_rps":   1000.0,
		}},
	})

	if code := doReq(chain, "t.tld", "9.9.9.9", "/"); code != http.StatusOK {
		t.Fatalf("first req = %d, want 200", code)
	}
	if code := doReq(chain, "t.tld", "9.9.9.9", "/"); code != http.StatusTooManyRequests {
		t.Fatalf("immediate follow-up = %d, want 429", code)
	}
	// Wait for token replenish at 50 rps -> 20ms per token; give headroom.
	time.Sleep(60 * time.Millisecond)
	if code := doReq(chain, "t.tld", "9.9.9.9", "/"); code != http.StatusOK {
		t.Fatalf("after sleep = %d, want 200", code)
	}
}

func TestAPIPathPrefixesTriggerAPIRPS(t *testing.T) {
	// Generous per-ip, stingy api. A /api/ request must hit api limits.
	_, chain := newEnabledFeature(t, map[string]any{
		"per_ip_rps":        1000.0,
		"per_ip_burst":      1000,
		"api_rps":           1.0,
		"api_burst":         2,
		"api_path_prefixes": []any{"/api/"},
		"global_rps":        1000.0,
	}, map[string]shared.FeatureSnapshot{
		"api.tld": {Enabled: true, Params: map[string]any{
			"per_ip_rps":        1000.0,
			"per_ip_burst":      1000,
			"api_rps":           1.0,
			"api_burst":         2,
			"api_path_prefixes": []any{"/api/"},
			"global_rps":        1000.0,
		}},
	})

	// Non-api path — should always pass.
	for i := 0; i < 10; i++ {
		if code := doReq(chain, "api.tld", "5.5.5.5", "/public/"+string(rune('a'+i))); code != http.StatusOK {
			t.Fatalf("public[%d] = %d, want 200", i, code)
		}
	}
	// API path — burst of 2 allowed, then blocked.
	if code := doReq(chain, "api.tld", "5.5.5.5", "/api/v1/a"); code != http.StatusOK {
		t.Fatalf("api burst[0] = %d, want 200", code)
	}
	if code := doReq(chain, "api.tld", "5.5.5.5", "/api/v1/b"); code != http.StatusOK {
		t.Fatalf("api burst[1] = %d, want 200", code)
	}
	if code := doReq(chain, "api.tld", "5.5.5.5", "/api/v1/c"); code != http.StatusTooManyRequests {
		t.Fatalf("api over burst = %d, want 429", code)
	}
}

func TestPerTenantIsolation(t *testing.T) {
	// Two tenants, tenant-a gets a tiny limit and tenant-b gets a fat
	// one. Exhausting tenant-a for IP X must not affect tenant-b for the
	// same IP X.
	_, chain := newEnabledFeature(t, map[string]any{
		"per_ip_rps":   1.0,
		"per_ip_burst": 1,
		"global_rps":   1000.0,
	}, map[string]shared.FeatureSnapshot{
		"a.tld": {Enabled: true, Params: map[string]any{
			"per_ip_rps":   1.0,
			"per_ip_burst": 1,
			"global_rps":   1000.0,
		}},
		"b.tld": {Enabled: true, Params: map[string]any{
			"per_ip_rps":   1000.0,
			"per_ip_burst": 1000,
			"global_rps":   1000.0,
		}},
	})

	ip := "10.0.0.1"
	if code := doReq(chain, "a.tld", ip, "/"); code != http.StatusOK {
		t.Fatalf("tenant-a first = %d, want 200", code)
	}
	if code := doReq(chain, "a.tld", ip, "/"); code != http.StatusTooManyRequests {
		t.Fatalf("tenant-a second = %d, want 429 (IP exhausted on A)", code)
	}
	// Same IP should be fine on tenant-b.
	for i := 0; i < 5; i++ {
		if code := doReq(chain, "b.tld", ip, "/"); code != http.StatusOK {
			t.Fatalf("tenant-b[%d] = %d, want 200 (isolation broken)", i, code)
		}
	}
}

func TestTrustXFFTogglesSourceOfIP(t *testing.T) {
	// Tenant-a trusts XFF, tenant-b does not.
	_, chain := newEnabledFeature(t, map[string]any{
		"per_ip_rps":   1.0,
		"per_ip_burst": 1,
		"global_rps":   1000.0,
	}, map[string]shared.FeatureSnapshot{
		"trust.tld": {Enabled: true, Params: map[string]any{
			"per_ip_rps":   1.0,
			"per_ip_burst": 1,
			"global_rps":   1000.0,
			"trust_xff":    true,
		}},
		"notrust.tld": {Enabled: true, Params: map[string]any{
			"per_ip_rps":   1.0,
			"per_ip_burst": 1,
			"global_rps":   1000.0,
			"trust_xff":    false,
		}},
	})

	sendWithXFF := func(host, remote, xff string) int {
		req := httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil)
		req.RemoteAddr = remote + ":12345"
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		tenant := &feature.TenantSnapshot{Host: host, Enabled: true}
		req = req.WithContext(feature.WithTenant(req.Context(), tenant))
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)
		return rec.Code
	}

	// trust.tld: RemoteAddr same, but XFF differs -> treated as different IPs.
	if code := sendWithXFF("trust.tld", "192.168.0.1", "11.0.0.1"); code != http.StatusOK {
		t.Fatalf("trust/first xff=11 = %d, want 200", code)
	}
	if code := sendWithXFF("trust.tld", "192.168.0.1", "22.0.0.1"); code != http.StatusOK {
		t.Fatalf("trust/first xff=22 = %d, want 200 (different source IPs)", code)
	}
	// Re-using xff=11 exhausts the bucket.
	if code := sendWithXFF("trust.tld", "192.168.0.1", "11.0.0.1"); code != http.StatusTooManyRequests {
		t.Fatalf("trust/second xff=11 = %d, want 429", code)
	}

	// notrust.tld: RemoteAddr same but XFF differs -> still same IP.
	if code := sendWithXFF("notrust.tld", "172.16.0.1", "33.0.0.1"); code != http.StatusOK {
		t.Fatalf("notrust/first = %d, want 200", code)
	}
	if code := sendWithXFF("notrust.tld", "172.16.0.1", "44.0.0.1"); code != http.StatusTooManyRequests {
		t.Fatalf("notrust/second (diff xff, same remote) = %d, want 429", code)
	}
}

func TestCleanupRemovesStaleBuckets(t *testing.T) {
	// 100ms cleanup interval with 100ms idle TTL: after >200ms the
	// sweeper fires and a stale entry is evicted.
	f := NewFeature()
	f.sweepInterval.Store(int64(30 * time.Millisecond))
	// Apply a tenant with an aggressive idle TTL.
	p := defaultParams()
	p.PerIPRPS = 1
	p.PerIPBurst = 1
	p.GlobalRPS = 1000
	p.CleanupInterval = 30 * time.Millisecond
	p.IdleTTL = 20 * time.Millisecond
	f.enabled.Store(true)
	f.ApplyTenants(map[string]params{"cleanup.tld": p})

	// Notify on every sweep so the test can synchronise.
	swept := make(chan struct{}, 32)
	f.testHook = func() {
		select {
		case swept <- struct{}{}:
		default:
		}
	}
	f.Start()
	t.Cleanup(f.Stop)

	// Touch a single per-IP bucket.
	state := f.stateFor("cleanup.tld")
	if state == nil {
		t.Fatalf("state missing for cleanup.tld")
	}
	state.ipBuckets.getOrCreate("7.7.7.7", time.Now())
	if got := state.ipBuckets.size(); got != 1 {
		t.Fatalf("after touch, size = %d, want 1", got)
	}

	// Drain at least two sweep ticks so the cutoff advances past IdleTTL.
	deadline := time.Now().Add(500 * time.Millisecond)
	ticks := 0
	for ticks < 3 && time.Now().Before(deadline) {
		select {
		case <-swept:
			ticks++
		case <-time.After(200 * time.Millisecond):
			t.Fatalf("sweep loop starved — only %d ticks", ticks)
		}
	}
	if got := state.ipBuckets.size(); got != 0 {
		t.Fatalf("after sweep, size = %d, want 0", got)
	}
}

func TestConcurrentReloadAndRequestsUnderRace(t *testing.T) {
	// 100 goroutines, reload loop, race detector.
	reg := feature.NewRegistry()
	f := NewFeature()
	reg.Register(f)
	reg.AddReloadObserver(FeatureName, f.Observe)
	f.Start()
	t.Cleanup(f.Stop)

	baseTenants := map[string]feature.TenantSnapshot{
		"t1.tld": {
			Host:    "t1.tld",
			Enabled: true,
			Features: map[string]shared.FeatureSnapshot{
				FeatureName: {Enabled: true, Params: map[string]any{
					"per_ip_rps": 10000.0, "per_ip_burst": 10000, "global_rps": 100000.0,
				}},
			},
		},
		"t2.tld": {
			Host:    "t2.tld",
			Enabled: true,
			Features: map[string]shared.FeatureSnapshot{
				FeatureName: {Enabled: true, Params: map[string]any{
					"per_ip_rps": 10000.0, "per_ip_burst": 10000, "global_rps": 100000.0,
				}},
			},
		},
	}
	if err := reg.Reload(feature.GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: {Enabled: true, Params: map[string]any{"global_rps": 100000.0}},
		},
	}, baseTenants); err != nil {
		t.Fatalf("initial Reload: %v", err)
	}
	f.ApplyFromSnapshots(baseTenants)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	chain := reg.BuildChain(inner)

	var (
		wg   sync.WaitGroup
		stop atomic.Bool
		errs atomic.Int64
	)

	for g := 0; g < 100; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			hosts := []string{"t1.tld", "t2.tld"}
			for !stop.Load() {
				host := hosts[id%2]
				req := httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil)
				req.RemoteAddr = "127.0.0.1:12345"
				req = req.WithContext(feature.WithTenant(req.Context(), &feature.TenantSnapshot{
					Host: host, Enabled: true,
				}))
				rec := httptest.NewRecorder()
				func() {
					defer func() {
						if r := recover(); r != nil {
							errs.Add(1)
						}
					}()
					chain.ServeHTTP(rec, req)
				}()
			}
		}(g)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer stop.Store(true)
		for i := 0; i < 40; i++ {
			rps := 1000.0 + float64(i)
			g := feature.GlobalsSnapshot{Features: map[string]shared.FeatureSnapshot{
				FeatureName: {Enabled: true, Params: map[string]any{"global_rps": rps}},
			}}
			newTenants := make(map[string]feature.TenantSnapshot, len(baseTenants))
			for h, ts := range baseTenants {
				newTenants[h] = ts
			}
			if err := reg.Reload(g, newTenants); err != nil {
				t.Errorf("Reload %d: %v", i, err)
			}
			f.ApplyFromSnapshots(newTenants)
		}
	}()

	wg.Wait()
	if errs.Load() != 0 {
		t.Fatalf("observed %d panics during concurrent load", errs.Load())
	}
}

func TestDisabledTenantIsPassThrough(t *testing.T) {
	// Tenant exists in registry but feature is disabled for it.
	reg := feature.NewRegistry()
	f := NewFeature()
	reg.Register(f)
	reg.AddReloadObserver(FeatureName, f.Observe)
	f.Start()
	t.Cleanup(f.Stop)

	tenants := map[string]feature.TenantSnapshot{
		"off.tld": {
			Host:    "off.tld",
			Enabled: true,
			Features: map[string]shared.FeatureSnapshot{
				FeatureName: {Enabled: false},
			},
		},
	}
	if err := reg.Reload(feature.GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: {Enabled: true},
		},
	}, tenants); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	f.ApplyFromSnapshots(tenants)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	chain := reg.BuildChain(inner)

	// Even with a tight global config, a disabled-tenant should not
	// accrue any rate-limit effect — 100 back-to-back must all 200.
	for i := 0; i < 100; i++ {
		if code := doReq(chain, "off.tld", "3.3.3.3", "/"); code != http.StatusOK {
			t.Fatalf("req[%d] on disabled tenant = %d, want 200", i, code)
		}
	}
}

func TestFeatureDisabledGloballyIsPassThrough(t *testing.T) {
	reg := feature.NewRegistry()
	f := NewFeature()
	reg.Register(f)
	reg.AddReloadObserver(FeatureName, f.Observe)
	f.Start()
	t.Cleanup(f.Stop)

	tenants := map[string]feature.TenantSnapshot{
		"x.tld": {
			Host:    "x.tld",
			Enabled: true,
			Features: map[string]shared.FeatureSnapshot{
				FeatureName: {Enabled: true, Params: map[string]any{
					"per_ip_rps": 0.1, "per_ip_burst": 1, "global_rps": 1.0,
				}},
			},
		},
	}
	if err := reg.Reload(feature.GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: {Enabled: false},
		},
	}, tenants); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	f.ApplyFromSnapshots(tenants)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	chain := reg.BuildChain(inner)

	// Feature disabled globally -> no enforcement.
	for i := 0; i < 20; i++ {
		if code := doReq(chain, "x.tld", "4.4.4.4", "/"); code != http.StatusOK {
			t.Fatalf("req[%d] = %d, want 200 (feature is disabled globally)", i, code)
		}
	}
}

func TestValidateRejectsBadParams(t *testing.T) {
	f := NewFeature()
	cases := []struct {
		name   string
		params map[string]any
	}{
		{"negative per_ip_rps", map[string]any{"per_ip_rps": -1.0}},
		{"negative per_ip_burst", map[string]any{"per_ip_burst": -1}},
		{"negative api_rps", map[string]any{"api_rps": -5.0}},
		{"negative api_burst", map[string]any{"api_burst": -1}},
		{"negative global_rps", map[string]any{"global_rps": -0.1}},
		{"bad action", map[string]any{"action_on_exceed": "bogus"}},
		{"negative cleanup", map[string]any{"cleanup_interval_seconds": -2}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := f.Validate(shared.FeatureSnapshot{Enabled: true, Params: tc.params})
			if err == nil {
				t.Fatalf("expected error for %q, got nil", tc.name)
			}
		})
	}
}

func TestValidateAcceptsGoodParams(t *testing.T) {
	f := NewFeature()
	p := map[string]any{
		"per_ip_rps":               10.0,
		"per_ip_burst":             20,
		"per_ip_conns":             50,
		"api_rps":                  5.0,
		"api_burst":                10,
		"api_path_prefixes":        []any{"/api/"},
		"global_rps":               1000.0,
		"cleanup_interval_seconds": 300,
		"trust_xff":                false,
		"action_on_exceed":         "429",
	}
	if err := f.Validate(shared.FeatureSnapshot{Enabled: true, Params: p}); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	// All three actions valid.
	for _, a := range []string{"429", "drop", "timeout"} {
		if err := f.Validate(shared.FeatureSnapshot{Enabled: true, Params: map[string]any{"action_on_exceed": a}}); err != nil {
			t.Fatalf("action %q: %v", a, err)
		}
	}
}

func TestNoTenantInContextIsPassThrough(t *testing.T) {
	_, chain := newEnabledFeature(t, map[string]any{
		"per_ip_rps": 0.01, "per_ip_burst": 1, "global_rps": 0.01,
	}, map[string]shared.FeatureSnapshot{
		"t.tld": {Enabled: true, Params: map[string]any{
			"per_ip_rps": 0.01, "per_ip_burst": 1, "global_rps": 0.01,
		}},
	})

	// No tenant in context -> skip.
	req := httptest.NewRequest(http.MethodGet, "http://whatever/", nil)
	req.RemoteAddr = "1.1.1.1:1"
	for i := 0; i < 20; i++ {
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("no-tenant req[%d] = %d, want 200", i, rec.Code)
		}
	}
}

func TestUnknownTenantIsPassThrough(t *testing.T) {
	_, chain := newEnabledFeature(t, map[string]any{
		"per_ip_rps": 0.01, "per_ip_burst": 1, "global_rps": 0.01,
	}, map[string]shared.FeatureSnapshot{
		"known.tld": {Enabled: true, Params: map[string]any{
			"per_ip_rps": 0.01, "per_ip_burst": 1, "global_rps": 0.01,
		}},
	})

	// Tenant in context that doesn't match any configured state -> skip.
	for i := 0; i < 20; i++ {
		if code := doReq(chain, "unknown.tld", "6.6.6.6", "/"); code != http.StatusOK {
			t.Fatalf("unknown-tenant req[%d] = %d, want 200", i, code)
		}
	}
}

// TestSweepRemovesIdleConnTrackers confirms the sweeper evicts connCounts
// entries whose count has returned to zero and whose lastSeen is older
// than the cutoff, bounding memory against IPv6-rotation abuse.
func TestSweepRemovesIdleConnTrackers(t *testing.T) {
	p := defaultParams()
	p.PerIPConns = 10
	p.CleanupInterval = 10 * time.Millisecond
	p.IdleTTL = 10 * time.Millisecond
	state := newTenantState(p)

	// Seed 5 tracker entries touched "now", then age them manually.
	for i := 0; i < 5; i++ {
		ip := "2001:db8::" + string(rune('a'+i))
		tracker := state.getConnTracker(ip)
		// Simulate a request that arrived and departed: count returns
		// to zero, lastSeen still recent.
		tracker.count.Add(1)
		tracker.count.Add(-1)
		tracker.lastSeen.Store(time.Now().UnixNano())
	}
	if got := state.connCountsSize(); got != 5 {
		t.Fatalf("seed size = %d, want 5", got)
	}

	// Cutoff in the future — everything qualifies for sweeping.
	removed := state.sweepConnCounts(time.Now().Add(time.Second))
	if removed != 5 {
		t.Fatalf("removed = %d, want 5", removed)
	}
	if got := state.connCountsSize(); got != 0 {
		t.Fatalf("post-sweep size = %d, want 0", got)
	}
}

// TestSweepKeepsActiveConnTrackers confirms the sweeper does NOT evict
// entries that still hold open connections (count > 0), even when they
// look idle by lastSeen — a stale lastSeen on an active tracker would
// otherwise free a counter that other goroutines may still adjust.
func TestSweepKeepsActiveConnTrackers(t *testing.T) {
	p := defaultParams()
	p.PerIPConns = 10
	state := newTenantState(p)

	active := state.getConnTracker("10.0.0.1")
	active.count.Add(1) // one in-flight request
	active.lastSeen.Store(time.Now().Add(-time.Hour).UnixNano())

	idle := state.getConnTracker("10.0.0.2")
	idle.lastSeen.Store(time.Now().Add(-time.Hour).UnixNano())

	removed := state.sweepConnCounts(time.Now().Add(-time.Minute))
	if removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}
	if _, ok := state.connCounts.Load("10.0.0.1"); !ok {
		t.Fatalf("active tracker 10.0.0.1 was swept — must stay while count>0")
	}
	if _, ok := state.connCounts.Load("10.0.0.2"); ok {
		t.Fatalf("idle tracker 10.0.0.2 survived sweep — expected removed")
	}
}

// TestSweepBoundsMemoryUnderRotation exercises the full open-close cycle
// of the serve code path: 2000 distinct IPs cycle through connCounts,
// and a sweep with a forward-dated cutoff returns the map to size 0.
// Validates that the sweep removes every tracker left behind by the
// request handler's deferred count.Add(-1).
func TestSweepBoundsMemoryUnderRotation(t *testing.T) {
	f, chain := newEnabledFeature(t, map[string]any{
		"per_ip_rps":   1000.0,
		"per_ip_burst": 1000,
		"per_ip_conns": 10,
		"global_rps":   100000.0,
	}, map[string]shared.FeatureSnapshot{
		"rot.tld": {Enabled: true, Params: map[string]any{
			"per_ip_rps":   1000.0,
			"per_ip_burst": 1000,
			"per_ip_conns": 10,
			"global_rps":   100000.0,
		}},
	})

	// Fire 2000 distinct IPs through the chain. Each request takes the
	// concurrent-connection path (PerIPConns > 0) and creates a
	// connTracker entry.
	for i := 0; i < 2000; i++ {
		ip := "10." + itoa(i/65025) + "." + itoa((i/255)%255) + "." + itoa(i%255)
		if code := doReq(chain, "rot.tld", ip, "/"); code != http.StatusOK {
			t.Fatalf("rotation req %d (ip=%s) = %d", i, ip, code)
		}
	}

	state := f.stateFor("rot.tld")
	if state == nil {
		t.Fatalf("state missing")
	}
	if got := state.connCountsSize(); got < 1000 {
		t.Fatalf("pre-sweep size = %d, want >=1000", got)
	}

	// Forward-dated cutoff: every idle tracker qualifies.
	state.sweepConnCounts(time.Now().Add(time.Hour))
	if got := state.connCountsSize(); got != 0 {
		t.Fatalf("post-sweep size = %d, want 0", got)
	}
}

// itoa is a tiny non-negative int stringifier used by the rotation test
// to avoid pulling in strconv's wide surface for a single hot loop.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [4]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func TestActionOnExceedDrop(t *testing.T) {
	// drop action on an httptest.ResponseRecorder (no hijacker) falls
	// back to 400 with empty body.
	_, chain := newEnabledFeature(t, map[string]any{
		"per_ip_rps": 1.0, "per_ip_burst": 1, "global_rps": 1000.0,
	}, map[string]shared.FeatureSnapshot{
		"d.tld": {Enabled: true, Params: map[string]any{
			"per_ip_rps":       1.0,
			"per_ip_burst":     1,
			"global_rps":       1000.0,
			"action_on_exceed": "drop",
		}},
	})
	if code := doReq(chain, "d.tld", "5.5.5.5", "/"); code != http.StatusOK {
		t.Fatalf("first = %d", code)
	}
	if code := doReq(chain, "d.tld", "5.5.5.5", "/"); code != http.StatusBadRequest {
		t.Fatalf("second drop = %d, want 400 (hijack fallback)", code)
	}
}
