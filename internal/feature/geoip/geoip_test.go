package geoip

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/oschwald/maxminddb-golang"

	"gateway/internal/feature"
	"gateway/internal/shared"
)

// stubResolver returns a canned snapshot for every Resolve call.
type stubResolver struct {
	snap shared.FeatureSnapshot
}

func (s *stubResolver) Resolve(*http.Request, string) shared.FeatureSnapshot {
	return s.snap
}

// okHandler records that the inner handler ran and writes 200.
type okHandler struct {
	ran atomic.Bool
}

func (h *okHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	h.ran.Store(true)
	w.WriteHeader(http.StatusOK)
}

// quietLogger returns a logger that discards everything so tests stay
// silent under -v.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

// newFeatureWithLookup builds a Feature wired to an injected LookupFunc
// for "test.mmdb" and configured so Validate skips disk existence checks.
func newFeatureWithLookup(t *testing.T, lookup LookupFunc) *Feature {
	t.Helper()
	f := New().WithLogger(quietLogger())
	f.WithLookupFunc("test.mmdb", lookup)
	return f
}

// baseParams returns a canonical params map for tests.
func baseParams(countries []any, action string, trustXFF bool) map[string]any {
	return map[string]any{
		"db_path":         "test.mmdb",
		"block_countries": countries,
		"action":          action,
		"trust_xff":       trustXFF,
	}
}

func TestValidateRejectsBadAction(t *testing.T) {
	f := newFeatureWithLookup(t, nil)
	cfg := shared.FeatureSnapshot{
		Enabled: true,
		Params:  baseParams([]any{"CN"}, "banana", false),
	}
	if err := f.Validate(cfg); err == nil {
		t.Fatal("expected invalid-action error, got nil")
	}
}

func TestValidateRejectsBadCountry(t *testing.T) {
	f := newFeatureWithLookup(t, nil)
	for _, bad := range []any{"c1", "CHN", "??", "c", ""} {
		cfg := shared.FeatureSnapshot{
			Enabled: true,
			Params:  baseParams([]any{bad}, "404", false),
		}
		if err := f.Validate(cfg); err == nil {
			t.Fatalf("expected error for country %q, got nil", bad)
		}
	}
}

func TestValidateRequiresDBPath(t *testing.T) {
	f := New().WithLogger(quietLogger())
	cfg := shared.FeatureSnapshot{
		Enabled: true,
		Params: map[string]any{
			"block_countries": []any{"CN"},
			"action":          "404",
		},
	}
	if err := f.Validate(cfg); err == nil {
		t.Fatal("expected error when db_path is missing")
	}
}

func TestValidatePassesWhenDisabled(t *testing.T) {
	f := New().WithLogger(quietLogger())
	cfg := shared.FeatureSnapshot{
		Enabled: false,
		Params:  baseParams([]any{"garbage"}, "nonsense", false),
	}
	if err := f.Validate(cfg); err != nil {
		t.Fatalf("disabled cfg should skip validation, got %v", err)
	}
}

func TestValidateChecksFileExistsWhenNoInjection(t *testing.T) {
	f := New().WithLogger(quietLogger())
	cfg := shared.FeatureSnapshot{
		Enabled: true,
		Params:  baseParams([]any{"CN"}, "404", false),
	}
	if err := f.Validate(cfg); err == nil {
		t.Fatal("expected stat error for missing test.mmdb")
	}
	// And with an existing file it should pass.
	dir := t.TempDir()
	p := filepath.Join(dir, "geo.mmdb")
	if err := os.WriteFile(p, []byte("stub"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg.Params["db_path"] = p
	if err := f.Validate(cfg); err != nil {
		t.Fatalf("unexpected validate error: %v", err)
	}
}

func TestMiddlewareDisabledIsPassThrough(t *testing.T) {
	f := newFeatureWithLookup(t, func(net.IP) (string, error) {
		return "CN", nil // would block, but feature is disabled
	})
	// No Observe call = enabled stays false.
	inner := &okHandler{}
	mw := f.Middleware(&stubResolver{snap: shared.FeatureSnapshot{Enabled: false}})
	h := mw(inner)

	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.RemoteAddr = "203.0.113.9:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !inner.ran.Load() {
		t.Fatal("inner handler did not run when feature disabled")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestMiddlewareBlocksCountryInGlobals(t *testing.T) {
	f := newFeatureWithLookup(t, func(net.IP) (string, error) { return "CN", nil })
	cfg := shared.FeatureSnapshot{
		Enabled: true,
		Params:  baseParams([]any{"CN"}, "404", false),
	}
	f.Observe(cfg, nil)

	inner := &okHandler{}
	mw := f.Middleware(&stubResolver{snap: cfg})
	h := mw(inner)

	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.RemoteAddr = "203.0.113.9:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if inner.ran.Load() {
		t.Fatal("inner handler ran despite blocked country")
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestMiddlewarePassesAllowedCountry(t *testing.T) {
	f := newFeatureWithLookup(t, func(net.IP) (string, error) { return "US", nil })
	cfg := shared.FeatureSnapshot{
		Enabled: true,
		Params:  baseParams([]any{"CN", "IR", "RU"}, "404", false),
	}
	f.Observe(cfg, nil)

	inner := &okHandler{}
	mw := f.Middleware(&stubResolver{snap: cfg})
	h := mw(inner)

	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.RemoteAddr = "203.0.113.9:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !inner.ran.Load() {
		t.Fatal("inner handler did not run for allowed country")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestMiddlewareBypassesBadIP(t *testing.T) {
	var called atomic.Int64
	f := newFeatureWithLookup(t, func(net.IP) (string, error) {
		called.Add(1)
		return "CN", nil
	})
	cfg := shared.FeatureSnapshot{
		Enabled: true,
		Params:  baseParams([]any{"CN"}, "404", false),
	}
	f.Observe(cfg, nil)

	inner := &okHandler{}
	mw := f.Middleware(&stubResolver{snap: cfg})
	h := mw(inner)

	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.RemoteAddr = "not-an-ip"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !inner.ran.Load() {
		t.Fatal("inner handler should have run for unparseable IP")
	}
	if called.Load() != 0 {
		t.Fatal("lookup should not have been called for unparseable IP")
	}
}

func TestMiddlewareLookupErrorBypasses(t *testing.T) {
	f := newFeatureWithLookup(t, func(net.IP) (string, error) {
		return "", errors.New("boom")
	})
	cfg := shared.FeatureSnapshot{
		Enabled: true,
		Params:  baseParams([]any{"CN"}, "404", false),
	}
	f.Observe(cfg, nil)

	inner := &okHandler{}
	mw := f.Middleware(&stubResolver{snap: cfg})
	h := mw(inner)

	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.RemoteAddr = "203.0.113.9:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !inner.ran.Load() {
		t.Fatal("inner handler should run when lookup errors")
	}
}

func TestMiddlewareTenantOverrideWins(t *testing.T) {
	// Globals: enabled with an empty country list (no-op). Tenant: blocks CN.
	f := newFeatureWithLookup(t, func(net.IP) (string, error) { return "CN", nil })
	globals := shared.FeatureSnapshot{
		Enabled: true,
		Params:  baseParams([]any{}, "404", false),
	}
	tenantCfg := shared.FeatureSnapshot{
		Enabled: true,
		Params:  baseParams([]any{"CN"}, "429", false),
	}
	f.Observe(globals, map[string]shared.FeatureSnapshot{"blocky.tld": tenantCfg})

	inner := &okHandler{}
	// Resolver always returns the tenant-level cfg for this test.
	mw := f.Middleware(&stubResolver{snap: tenantCfg})
	h := mw(inner)

	req := httptest.NewRequest(http.MethodGet, "http://blocky.tld/", nil)
	req.RemoteAddr = "203.0.113.9:1234"
	req = req.WithContext(feature.WithTenant(req.Context(), &feature.TenantSnapshot{
		Host:    "blocky.tld",
		Enabled: true,
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: tenantCfg,
		},
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if inner.ran.Load() {
		t.Fatal("inner should not have run; tenant override should block")
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 from tenant action override", rec.Code)
	}
}

func TestMiddlewareTrustXFF(t *testing.T) {
	var seen atomic.Value // stores net.IP.String()
	f := newFeatureWithLookup(t, func(ip net.IP) (string, error) {
		seen.Store(ip.String())
		if ip.String() == "198.51.100.77" {
			return "IR", nil
		}
		return "US", nil
	})

	cfgTrust := shared.FeatureSnapshot{
		Enabled: true,
		Params:  baseParams([]any{"IR"}, "404", true),
	}
	cfgNoTrust := shared.FeatureSnapshot{
		Enabled: true,
		Params:  baseParams([]any{"IR"}, "404", false),
	}

	// Case 1: trust_xff=true → blocks based on XFF last hop.
	f.Observe(cfgTrust, nil)
	inner1 := &okHandler{}
	h1 := f.Middleware(&stubResolver{snap: cfgTrust})(inner1)

	req1 := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req1.RemoteAddr = "10.0.0.1:42"
	req1.Header.Set("X-Forwarded-For", "9.9.9.9, 198.51.100.77")
	rec1 := httptest.NewRecorder()
	h1.ServeHTTP(rec1, req1)
	if inner1.ran.Load() {
		t.Fatal("trust_xff=true: inner should not run when XFF last hop is blocked country")
	}
	if rec1.Code != http.StatusNotFound {
		t.Fatalf("trust_xff=true: status = %d, want 404", rec1.Code)
	}

	// Case 2: trust_xff=false → uses RemoteAddr → US → pass.
	f.Observe(cfgNoTrust, nil)
	inner2 := &okHandler{}
	h2 := f.Middleware(&stubResolver{snap: cfgNoTrust})(inner2)

	req2 := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req2.RemoteAddr = "10.0.0.1:42"
	req2.Header.Set("X-Forwarded-For", "198.51.100.77")
	rec2 := httptest.NewRecorder()
	h2.ServeHTTP(rec2, req2)
	if !inner2.ran.Load() {
		t.Fatal("trust_xff=false: inner should run when RemoteAddr country is allowed")
	}
	if rec2.Code != http.StatusOK {
		t.Fatalf("trust_xff=false: status = %d, want 200", rec2.Code)
	}
}

func TestMiddlewareAction429(t *testing.T) {
	f := newFeatureWithLookup(t, func(net.IP) (string, error) { return "RU", nil })
	cfg := shared.FeatureSnapshot{
		Enabled: true,
		Params:  baseParams([]any{"RU"}, "429", false),
	}
	f.Observe(cfg, nil)

	inner := &okHandler{}
	h := f.Middleware(&stubResolver{snap: cfg})(inner)

	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.RemoteAddr = "203.0.113.9:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
}

func TestObserveRefcountOpensAndCloses(t *testing.T) {
	var openCount atomic.Int64

	// Hook the reader-open path so no real file is required. The returned
	// *maxminddb.Reader is zero-valued; its Close() is a no-op in that
	// state, which is exactly what the refcount test needs. We observe
	// lifecycle by inspecting the feature's readers map.
	f := New().WithLogger(quietLogger())
	f.openReader = func(path string) (*maxminddb.Reader, error) {
		openCount.Add(1)
		return &maxminddb.Reader{}, nil
	}

	cfgA := shared.FeatureSnapshot{
		Enabled: true,
		Params: map[string]any{
			"db_path":         "/tmp/geo-a.mmdb",
			"block_countries": []any{"CN"},
			"action":          "404",
		},
	}
	cfgB := shared.FeatureSnapshot{
		Enabled: true,
		Params: map[string]any{
			"db_path":         "/tmp/geo-b.mmdb",
			"block_countries": []any{"RU"},
			"action":          "404",
		},
	}

	// First reload: only path A referenced.
	f.Observe(cfgA, nil)
	if openCount.Load() != 1 {
		t.Fatalf("opened %d times, want 1", openCount.Load())
	}
	if got := f.readerPaths(); len(got) != 1 || got[0] != "/tmp/geo-a.mmdb" {
		t.Fatalf("readers after first observe = %v, want [/tmp/geo-a.mmdb]", got)
	}

	// Second reload: path A still referenced (globals) + B via tenant.
	f.Observe(cfgA, map[string]shared.FeatureSnapshot{"t.tld": cfgB})
	if openCount.Load() != 2 {
		t.Fatalf("opened %d times, want 2", openCount.Load())
	}
	if got := len(f.readerPaths()); got != 2 {
		t.Fatalf("reader count after second observe = %d, want 2", got)
	}

	// Third reload: only B referenced. A must be closed and dropped.
	f.Observe(cfgB, nil)
	paths := f.readerPaths()
	if len(paths) != 1 || paths[0] != "/tmp/geo-b.mmdb" {
		t.Fatalf("after third observe readers = %v, want [/tmp/geo-b.mmdb]", paths)
	}
	// No new opens since B was already open.
	if openCount.Load() != 2 {
		t.Fatalf("third observe should not reopen existing paths; opens = %d want 2", openCount.Load())
	}

	// Close releases the remaining handle.
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := len(f.readerPaths()); got != 0 {
		t.Fatalf("after Close, readers = %d, want 0", got)
	}
}

func TestObserveFlipsEnabledFlag(t *testing.T) {
	f := newFeatureWithLookup(t, func(net.IP) (string, error) { return "CN", nil })
	if f.enabled.Load() {
		t.Fatal("enabled should start false")
	}
	f.Observe(shared.FeatureSnapshot{Enabled: false}, nil)
	if f.enabled.Load() {
		t.Fatal("enabled should remain false after disabled observe")
	}
	f.Observe(shared.FeatureSnapshot{
		Enabled: true,
		Params:  baseParams([]any{"CN"}, "404", false),
	}, nil)
	if !f.enabled.Load() {
		t.Fatal("enabled should be true after enabled globals")
	}
	f.Observe(shared.FeatureSnapshot{Enabled: false}, map[string]shared.FeatureSnapshot{
		"t.tld": {
			Enabled: true,
			Params:  baseParams([]any{"CN"}, "404", false),
		},
	})
	if !f.enabled.Load() {
		t.Fatal("enabled should be true when at least one tenant enabled")
	}
	f.Observe(shared.FeatureSnapshot{Enabled: false}, nil)
	if f.enabled.Load() {
		t.Fatal("enabled should go false when nothing references the feature")
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	f := New().WithLogger(quietLogger())
	if err := f.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

func TestFeatureName(t *testing.T) {
	if n := New().Name(); n != "geoip" {
		t.Fatalf("Name() = %q, want geoip", n)
	}
}

func TestBlocklistImplementsFeatureInterface(t *testing.T) {
	var _ feature.Feature = (*Feature)(nil)
}

// TestMiddlewareRaceSafeUnderReload drives concurrent requests while
// Observe swaps configuration and reader refs. -race must stay clean.
func TestMiddlewareRaceSafeUnderReload(t *testing.T) {
	var openCount atomic.Int64
	f := New().WithLogger(quietLogger())
	f.openReader = func(path string) (*maxminddb.Reader, error) {
		openCount.Add(1)
		return &maxminddb.Reader{}, nil
	}

	// Inject a deterministic lookup for every path we'll reference so that
	// the hot path never tries to dereference the stub reader.
	f.WithLookupFunc("/tmp/a.mmdb", func(net.IP) (string, error) { return "CN", nil })
	f.WithLookupFunc("/tmp/b.mmdb", func(net.IP) (string, error) { return "US", nil })

	inner := &okHandler{}
	mw := f.Middleware(&stubResolver{snap: shared.FeatureSnapshot{
		Enabled: true,
		Params:  baseParams([]any{"CN"}, "404", false),
	}})
	h := mw(inner)

	// Seed.
	f.Observe(shared.FeatureSnapshot{
		Enabled: true,
		Params: map[string]any{
			"db_path":         "/tmp/a.mmdb",
			"block_countries": []any{"CN"},
			"action":          "404",
		},
	}, nil)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
				req.RemoteAddr = "203.0.113.9:1234"
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
			}
		}()
	}

	for i := 0; i < 100; i++ {
		path := "/tmp/a.mmdb"
		if i%2 == 1 {
			path = "/tmp/b.mmdb"
		}
		f.Observe(shared.FeatureSnapshot{
			Enabled: true,
			Params: map[string]any{
				"db_path":         path,
				"block_countries": []any{"CN"},
				"action":          "404",
			},
		}, nil)
	}

	close(stop)
	wg.Wait()
}

// readerPaths returns the currently tracked db_path keys. Used by tests
// to assert reader lifecycle without poking at unexported maps directly
// from another package.
func (f *Feature) readerPaths() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]string, 0, len(f.readers))
	for p := range f.readers {
		out = append(out, p)
	}
	return out
}
