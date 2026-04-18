package ttlblock

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gateway/internal/feature"
	"gateway/internal/shared"
)

// newFeatureWithStore builds a Feature wired to a store under t.TempDir().
// It is the workhorse helper for middleware tests.
func newFeatureWithStore(t *testing.T, action shared.BlockAction, trustXFF bool) *Feature {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "ttlblock.db")

	f := New()
	snap := shared.FeatureSnapshot{
		Enabled: true,
		Params: map[string]any{
			"db_path":       dbPath,
			"default_ttl":   "1h",
			"action":        string(action),
			"salted_hashes": false,
			"salt_file":     "",
			"max_entries":   100,
			"trust_xff":     trustXFF,
		},
	}
	f.Observe(snap)
	t.Cleanup(func() {
		f.Stop()
		if s := f.Store(); s != nil {
			_ = s.Close()
		}
	})
	return f
}

// buildChain wires the feature into a minimal pipeline with a default
// "inner" handler that records whether the request made it past the
// middleware.
func buildChain(f *Feature) (http.Handler, *atomic.Bool) {
	reached := &atomic.Bool{}
	reg := feature.NewRegistry()
	reg.Register(f)
	_ = reg.Reload(feature.GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: {Enabled: f.enabled.Load()},
		},
	}, nil)
	return reg.BuildChain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(true)
		w.WriteHeader(http.StatusOK)
	})), reached
}

func TestFeature_NameConstant(t *testing.T) {
	if FeatureName != "ttl_blocklist" {
		t.Fatalf("FeatureName = %q, want ttl_blocklist", FeatureName)
	}
	if (New()).Name() != FeatureName {
		t.Fatalf("Name() != FeatureName")
	}
}

func TestFeature_Validate(t *testing.T) {
	f := New()

	// Disabled snapshot is always OK.
	if err := f.Validate(shared.FeatureSnapshot{Enabled: false, Params: map[string]any{"action": "garbage"}}); err != nil {
		t.Fatalf("disabled snapshot must pass validation, got %v", err)
	}

	// Good snapshot.
	ok := shared.FeatureSnapshot{Enabled: true, Params: map[string]any{
		"default_ttl": "30m",
		"action":      "404",
		"max_entries": 10,
	}}
	if err := f.Validate(ok); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// Bad duration.
	if err := f.Validate(shared.FeatureSnapshot{Enabled: true, Params: map[string]any{"default_ttl": "not-a-duration"}}); err == nil {
		t.Fatalf("expected invalid default_ttl to fail")
	}
	// Bad action.
	if err := f.Validate(shared.FeatureSnapshot{Enabled: true, Params: map[string]any{"action": "explode"}}); err == nil {
		t.Fatalf("expected invalid action to fail")
	}
	// Negative max_entries.
	if err := f.Validate(shared.FeatureSnapshot{Enabled: true, Params: map[string]any{"max_entries": -1}}); err == nil {
		t.Fatalf("expected negative max_entries to fail")
	}
}

func TestFeature_ParseParamsDefaults(t *testing.T) {
	p := parseParams(nil)
	if p.DefaultTTL != 24*time.Hour {
		t.Fatalf("DefaultTTL default = %v", p.DefaultTTL)
	}
	if p.Action != shared.BlockActionDrop {
		t.Fatalf("Action default = %q", p.Action)
	}
	if !p.SaltedHashes {
		t.Fatalf("SaltedHashes should default to true")
	}
	if p.MaxEntries != 100000 {
		t.Fatalf("MaxEntries default = %d", p.MaxEntries)
	}
	if p.TrustXFF {
		t.Fatalf("TrustXFF should default to false")
	}
}

func TestFeature_MiddlewareDisabledPassesThrough(t *testing.T) {
	f := New()
	f.Observe(shared.FeatureSnapshot{Enabled: false})

	chain, reached := buildChain(f)

	req := httptest.NewRequest(http.MethodGet, "http://example.tld/", nil)
	req.RemoteAddr = "1.2.3.4:55555"
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)

	if !reached.Load() {
		t.Fatalf("inner handler must run when feature is disabled")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestFeature_MiddlewareAppliesAction_404(t *testing.T) {
	f := newFeatureWithStore(t, shared.BlockActionNotFound, false)

	s := f.Store()
	if s == nil {
		t.Fatalf("store not initialised")
	}
	if err := s.Add("example.tld", "1.2.3.4", time.Hour, "test", 100); err != nil {
		t.Fatalf("Add: %v", err)
	}

	chain, reached := buildChain(f)

	req := httptest.NewRequest(http.MethodGet, "http://example.tld/", nil)
	req.RemoteAddr = "1.2.3.4:55555"
	req = req.WithContext(feature.WithTenant(req.Context(), &feature.TenantSnapshot{
		Host:    "example.tld",
		Enabled: true,
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: {Enabled: true},
		},
	}))
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)

	if reached.Load() {
		t.Fatalf("inner handler must not run when blocked")
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestFeature_MiddlewareAppliesAction_429(t *testing.T) {
	f := newFeatureWithStore(t, shared.BlockActionTooMany, false)
	_ = f.Store().Add("example.tld", "1.2.3.4", time.Hour, "", 100)

	chain, _ := buildChain(f)

	req := httptest.NewRequest(http.MethodGet, "http://example.tld/", nil)
	req.RemoteAddr = "1.2.3.4:55555"
	req = req.WithContext(feature.WithTenant(req.Context(), &feature.TenantSnapshot{
		Host:    "example.tld",
		Enabled: true,
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: {Enabled: true},
		},
	}))
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatalf("Retry-After header missing on 429")
	}
}

// hijackableRecorder is an http.ResponseWriter that also implements
// http.Hijacker — needed so the "drop" action exercises the happy path
// instead of its 400 fallback.
type hijackableRecorder struct {
	*httptest.ResponseRecorder
	hijacked atomic.Bool
}

func newHijackableRecorder() *hijackableRecorder {
	return &hijackableRecorder{ResponseRecorder: httptest.NewRecorder()}
}

func (h *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked.Store(true)
	// Return a pipe end the caller can close without upsetting anyone.
	c1, _ := net.Pipe()
	return c1, bufio.NewReadWriter(bufio.NewReader(c1), bufio.NewWriter(c1)), nil
}

func TestFeature_MiddlewareAppliesAction_Drop(t *testing.T) {
	f := newFeatureWithStore(t, shared.BlockActionDrop, false)
	_ = f.Store().Add("example.tld", "1.2.3.4", time.Hour, "", 100)

	chain, reached := buildChain(f)

	req := httptest.NewRequest(http.MethodGet, "http://example.tld/", nil)
	req.RemoteAddr = "1.2.3.4:55555"
	req = req.WithContext(feature.WithTenant(req.Context(), &feature.TenantSnapshot{
		Host:    "example.tld",
		Enabled: true,
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: {Enabled: true},
		},
	}))
	rec := newHijackableRecorder()
	chain.ServeHTTP(rec, req)

	if reached.Load() {
		t.Fatalf("inner handler must not run when dropped")
	}
	if !rec.hijacked.Load() {
		t.Fatalf("drop action should hijack the connection")
	}
}

func TestFeature_MiddlewareAppliesAction_DropFallback(t *testing.T) {
	f := newFeatureWithStore(t, shared.BlockActionDrop, false)
	_ = f.Store().Add("example.tld", "1.2.3.4", time.Hour, "", 100)

	chain, _ := buildChain(f)

	req := httptest.NewRequest(http.MethodGet, "http://example.tld/", nil)
	req.RemoteAddr = "1.2.3.4:55555"
	req = req.WithContext(feature.WithTenant(req.Context(), &feature.TenantSnapshot{
		Host:    "example.tld",
		Enabled: true,
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: {Enabled: true},
		},
	}))
	// httptest.ResponseRecorder does not implement Hijacker — expect fallback.
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("fallback should write 400, got %d", rec.Code)
	}
}

func TestFeature_MiddlewareMissingRemoteAddrPassesThrough(t *testing.T) {
	f := newFeatureWithStore(t, shared.BlockActionNotFound, false)
	_ = f.Store().Add("example.tld", "1.2.3.4", time.Hour, "", 100)

	chain, reached := buildChain(f)

	req := httptest.NewRequest(http.MethodGet, "http://example.tld/", nil)
	req.RemoteAddr = ""
	req = req.WithContext(feature.WithTenant(req.Context(), &feature.TenantSnapshot{
		Host:    "example.tld",
		Enabled: true,
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: {Enabled: true},
		},
	}))
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)

	if !reached.Load() {
		t.Fatalf("requests without an IP should pass through")
	}
}

func TestFeature_MiddlewareTrustsXFFWhenEnabled(t *testing.T) {
	f := newFeatureWithStore(t, shared.BlockActionNotFound, true)
	_ = f.Store().Add("example.tld", "198.51.100.7", time.Hour, "", 100)

	chain, _ := buildChain(f)

	req := httptest.NewRequest(http.MethodGet, "http://example.tld/", nil)
	req.RemoteAddr = "1.2.3.4:55555" // not blocked
	req.Header.Set("X-Forwarded-For", "198.51.100.7, 10.0.0.1")
	req = req.WithContext(feature.WithTenant(req.Context(), &feature.TenantSnapshot{
		Host:    "example.tld",
		Enabled: true,
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: {Enabled: true},
		},
	}))
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected XFF leftmost entry to be consulted; got %d", rec.Code)
	}
}

func TestFeature_MiddlewareIgnoresXFFWhenDisabled(t *testing.T) {
	f := newFeatureWithStore(t, shared.BlockActionNotFound, false)
	_ = f.Store().Add("example.tld", "198.51.100.7", time.Hour, "", 100)

	chain, reached := buildChain(f)

	req := httptest.NewRequest(http.MethodGet, "http://example.tld/", nil)
	req.RemoteAddr = "1.2.3.4:55555"
	req.Header.Set("X-Forwarded-For", "198.51.100.7")
	req = req.WithContext(feature.WithTenant(req.Context(), &feature.TenantSnapshot{
		Host:    "example.tld",
		Enabled: true,
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: {Enabled: true},
		},
	}))
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)

	if !reached.Load() {
		t.Fatalf("with trust_xff=false, request must pass through")
	}
}

func TestFeature_MiddlewareTenantDisabledPassesThrough(t *testing.T) {
	f := newFeatureWithStore(t, shared.BlockActionNotFound, false)
	_ = f.Store().Add("example.tld", "1.2.3.4", time.Hour, "", 100)

	chain, reached := buildChain(f)

	req := httptest.NewRequest(http.MethodGet, "http://example.tld/", nil)
	req.RemoteAddr = "1.2.3.4:55555"
	req = req.WithContext(feature.WithTenant(req.Context(), &feature.TenantSnapshot{
		Host:    "example.tld",
		Enabled: true,
		Features: map[string]shared.FeatureSnapshot{
			// Explicit override disables the feature for this tenant.
			FeatureName: {Enabled: false},
		},
	}))
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)

	if !reached.Load() {
		t.Fatalf("tenant override disabling must skip the feature")
	}
}

func TestFeature_ObserveReopensStoreOnPathChange(t *testing.T) {
	dir := t.TempDir()
	path1 := filepath.Join(dir, "db1")
	path2 := filepath.Join(dir, "db2")

	f := New()
	f.Observe(shared.FeatureSnapshot{Enabled: true, Params: map[string]any{
		"db_path":       path1,
		"salted_hashes": false,
	}})
	s1 := f.Store()
	if s1 == nil {
		t.Fatalf("store 1 not opened")
	}

	f.Observe(shared.FeatureSnapshot{Enabled: true, Params: map[string]any{
		"db_path":       path2,
		"salted_hashes": false,
	}})
	s2 := f.Store()
	if s2 == nil {
		t.Fatalf("store 2 not opened")
	}
	if s1 == s2 {
		t.Fatalf("store pointer did not change across db_path change")
	}

	// s1 should now be closed: a write against it must error.
	if err := s1.Add("x", "y", time.Hour, "", 0); err == nil {
		t.Fatalf("old store should be closed after path change")
	} else if !errors.Is(err, errors.New("")) {
		// We only check that some error was returned; bbolt returns a
		// db-closed sentinel that isn't safely inspectable across versions.
		_ = err
	}

	t.Cleanup(func() {
		f.Stop()
		if s := f.Store(); s != nil {
			_ = s.Close()
		}
	})
}

func TestFeature_ObserveDisablesClosesStore(t *testing.T) {
	f := New()
	f.Observe(shared.FeatureSnapshot{Enabled: true, Params: map[string]any{
		"db_path":       filepath.Join(t.TempDir(), "db"),
		"salted_hashes": false,
	}})
	if f.Store() == nil {
		t.Fatalf("store not opened")
	}
	f.Observe(shared.FeatureSnapshot{Enabled: false})
	if f.Store() != nil {
		t.Fatalf("store should be nil after disable")
	}
}

func TestFeature_SweeperGoroutine(t *testing.T) {
	f := newFeatureWithStore(t, shared.BlockActionNotFound, false)

	clock := newFakeClock(time.Date(2026, 4, 18, 0, 0, 0, 0, time.UTC))
	f.Store().SetClock(clock.now)

	_ = f.Store().Add("t", "1.1.1.1", 1*time.Second, "", 0)
	_ = f.Store().Add("t", "2.2.2.2", 10*time.Minute, "", 0)

	// Sweep cadence small enough that the test finishes in well under
	// a second, but large enough that we can assert ordering.
	f.SetSweepInterval(10 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	f.Start(ctx)

	// Advance clock past the 1s TTL and wait for the sweeper to notice.
	clock.advance(2 * time.Second)

	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if !f.Store().Contains("t", "1.1.1.1") {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if f.Store().Contains("t", "1.1.1.1") {
		t.Fatalf("expired entry was not swept within deadline")
	}
	if !f.Store().Contains("t", "2.2.2.2") {
		t.Fatalf("fresh entry swept by mistake")
	}

	f.Stop()
	// Start → Stop → Start again must work.
	f.Start(ctx)
	f.Stop()
}

func TestFeature_RegisterTenantsOverridesParams(t *testing.T) {
	f := newFeatureWithStore(t, shared.BlockActionNotFound, false)

	tenantSnap := feature.TenantSnapshot{
		Host:    "example.tld",
		Enabled: true,
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: {Enabled: true, Params: map[string]any{
				"action":    "429",
				"trust_xff": true,
			}},
		},
	}
	f.RegisterTenants(map[string]feature.TenantSnapshot{"example.tld": tenantSnap})

	p, ok := f.effectiveParams("example.tld")
	if !ok {
		t.Fatalf("tenant params not found")
	}
	if p.Action != shared.BlockActionTooMany {
		t.Fatalf("tenant action override not applied: %q", p.Action)
	}
	if !p.TrustXFF {
		t.Fatalf("tenant trust_xff override not applied")
	}

	// Unregistered tenant falls back to globals (drop).
	gp, ok := f.effectiveParams("other.tld")
	if !ok {
		t.Fatalf("fallback to globals failed")
	}
	if gp.Action != shared.BlockActionNotFound {
		t.Fatalf("fallback action = %q; want globals 404", gp.Action)
	}
}

func TestFeature_RegisterFeatureInRegistryAndReload(t *testing.T) {
	f := newFeatureWithStore(t, shared.BlockActionNotFound, false)

	reg := feature.NewRegistry()
	reg.Register(f)
	reg.AddReloadObserver(FeatureName, f.Observe)

	dir := t.TempDir()
	globals := feature.GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: {Enabled: true, Params: map[string]any{
				"db_path":       filepath.Join(dir, "db"),
				"action":        "404",
				"salted_hashes": false,
			}},
		},
	}
	if err := reg.Reload(globals, nil); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if !f.enabled.Load() {
		t.Fatalf("observer did not fire on Reload")
	}

	// Disable.
	globals.Features[FeatureName] = shared.FeatureSnapshot{Enabled: false}
	if err := reg.Reload(globals, nil); err != nil {
		t.Fatalf("Reload 2: %v", err)
	}
	if f.enabled.Load() {
		t.Fatalf("observer did not reflect disabled state")
	}
}

func TestFeature_ConcurrentObserveAndRequests(t *testing.T) {
	f := newFeatureWithStore(t, shared.BlockActionNotFound, false)
	_ = f.Store().Add("example.tld", "1.2.3.4", time.Hour, "", 0)

	chain, _ := buildChain(f)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Observer churn: repeatedly toggle enabled.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			f.Observe(shared.FeatureSnapshot{Enabled: true, Params: map[string]any{
				"db_path":       f.globalCfg.DBPath,
				"salted_hashes": false,
				"action":        "404",
			}})
			f.Observe(shared.FeatureSnapshot{Enabled: true, Params: map[string]any{
				"db_path":       f.globalCfg.DBPath,
				"salted_hashes": false,
				"action":        "429",
			}})
		}
	}()

	// Request churn.
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				req := httptest.NewRequest(http.MethodGet, "http://example.tld/", nil)
				req.RemoteAddr = "1.2.3.4:55555"
				req = req.WithContext(feature.WithTenant(req.Context(), &feature.TenantSnapshot{
					Host:    "example.tld",
					Enabled: true,
					Features: map[string]shared.FeatureSnapshot{
						FeatureName: {Enabled: true},
					},
				}))
				rec := httptest.NewRecorder()
				chain.ServeHTTP(rec, req)
			}
		}()
	}

	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}

func TestFeature_ResolveClientIPVariants(t *testing.T) {
	tests := []struct {
		name     string
		remote   string
		xff      string
		trustXFF bool
		want     string
	}{
		{"host_port", "1.2.3.4:55555", "", false, "1.2.3.4"},
		{"ipv6_host_port", "[2001:db8::1]:443", "", false, "2001:db8::1"},
		{"bare_ip", "1.2.3.4", "", false, "1.2.3.4"},
		{"xff_enabled_single", "1.2.3.4:1", "9.9.9.9", true, "9.9.9.9"},
		{"xff_enabled_list", "1.2.3.4:1", " 9.9.9.9 , 10.0.0.1 ", true, "9.9.9.9"},
		{"xff_disabled_uses_remote", "1.2.3.4:1", "9.9.9.9", false, "1.2.3.4"},
		{"xff_empty_falls_back", "1.2.3.4:1", "", true, "1.2.3.4"},
		{"empty_remote", "", "", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example.tld/", nil)
			req.RemoteAddr = tt.remote
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			got := resolveClientIP(req, tt.trustXFF)
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFeature_StartIsIdempotent(t *testing.T) {
	f := newFeatureWithStore(t, shared.BlockActionNotFound, false)
	f.SetSweepInterval(50 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	f.Start(ctx)
	f.Start(ctx)
	f.Start(ctx)
	// Stop also safe to call twice.
	f.Stop()
	f.Stop()
}

func TestFeature_SetStoreReplacesAndClosesOld(t *testing.T) {
	f := newFeatureWithStore(t, shared.BlockActionNotFound, false)
	old := f.Store()
	if old == nil {
		t.Fatalf("store not opened")
	}

	dir := t.TempDir()
	newStore, err := OpenStore(filepath.Join(dir, "new.db"), "")
	if err != nil {
		t.Fatalf("OpenStore new: %v", err)
	}
	f.SetStore(newStore)
	if f.Store() != newStore {
		t.Fatalf("SetStore did not replace the live store")
	}
	// old should have been closed; adding must error.
	if err := old.Add("t", "1.1.1.1", time.Hour, "", 0); err == nil {
		t.Fatalf("old store should be closed after SetStore")
	}
}
