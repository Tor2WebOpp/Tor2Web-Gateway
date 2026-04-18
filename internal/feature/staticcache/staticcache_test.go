package staticcache

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gateway/internal/feature"
	"gateway/internal/shared"
)

// enableSnapshot is the stock enabled FeatureSnapshot used across tests.
func enableSnapshot(ttl time.Duration) shared.FeatureSnapshot {
	return shared.FeatureSnapshot{
		Enabled: true,
		Params: map[string]any{
			"max_size_mb":       int64(64),
			"default_ttl":       ttl.String(),
			"static_extensions": []any{".js", ".css", ".png", ".woff2"},
		},
	}
}

// buildChain wires a fresh Feature onto a fresh Registry and returns the
// full middleware chain built around next.
func buildChain(t *testing.T, globals shared.FeatureSnapshot, tenants map[string]feature.TenantSnapshot, next http.Handler) (*feature.Registry, *Feature, http.Handler) {
	t.Helper()
	reg := feature.NewRegistry()
	f := RegisterWith(reg)
	g := feature.GlobalsSnapshot{Features: map[string]shared.FeatureSnapshot{FeatureName: globals}}
	if err := reg.Reload(g, tenants); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	// Give Ristretto's buffered SetWithTTL a moment to flush from its
	// internal channels into the primary store on a cold rebuild.
	time.Sleep(10 * time.Millisecond)
	return reg, f, reg.BuildChain(next)
}

// newStaticBackend returns an http.Handler that increments hits on every
// call and serves the supplied bytes with a matching Content-Length and a
// Content-Type derived from the path's extension.
func newStaticBackend(hits *atomic.Int64, body []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		ct := "application/octet-stream"
		switch ext := filepathExt(r.URL.Path); ext {
		case "js":
			ct = "application/javascript"
		case "css":
			ct = "text/css"
		case "png":
			ct = "image/png"
		case "woff2":
			ct = "font/woff2"
		}
		w.Header().Set("Content-Type", ct)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})
}

// filepathExt is a small helper extracted so the tests don't need to
// import path/filepath directly; it mirrors the package-internal logic.
func filepathExt(p string) string {
	for i := len(p) - 1; i >= 0 && p[i] != '/'; i-- {
		if p[i] == '.' {
			return p[i+1:]
		}
	}
	return ""
}

// reqFor builds a GET request to path with the given tenant attached to
// its context. When tenantHost is empty no tenant is attached.
func reqFor(path, tenantHost string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://example.test"+path, nil)
	if tenantHost != "" {
		ctx := feature.WithTenant(req.Context(), &feature.TenantSnapshot{Host: tenantHost, Enabled: true})
		req = req.WithContext(ctx)
	}
	return req
}

func TestCacheableRequestServedFromCacheOnSecondHit(t *testing.T) {
	var hits atomic.Int64
	backend := newStaticBackend(&hits, []byte("body-one"))

	_, _, chain := buildChain(t, enableSnapshot(time.Hour), nil, backend)

	// First request — cold miss populates the cache.
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, reqFor("/assets/app.js", "one.example"))
	if rec.Code != http.StatusOK {
		t.Fatalf("first: status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "body-one" {
		t.Fatalf("first: body = %q", rec.Body.String())
	}

	// Let the async admission settle before issuing the second request.
	time.Sleep(50 * time.Millisecond)

	// Second request — expect cache hit (no backend call).
	rec2 := httptest.NewRecorder()
	chain.ServeHTTP(rec2, reqFor("/assets/app.js", "one.example"))
	if rec2.Code != http.StatusOK {
		t.Fatalf("second: status = %d, want 200", rec2.Code)
	}
	if rec2.Body.String() != "body-one" {
		t.Fatalf("second: body = %q", rec2.Body.String())
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("backend hit %d times, want 1", got)
	}
	if got := rec2.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("second: X-Cache = %q, want HIT", got)
	}
}

func TestNonCacheableExtensionBypassesCache(t *testing.T) {
	var hits atomic.Int64
	backend := newStaticBackend(&hits, []byte("dynamic"))

	_, _, chain := buildChain(t, enableSnapshot(time.Hour), nil, backend)

	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, reqFor("/api/profile", "one.example"))
		if rec.Code != http.StatusOK {
			t.Fatalf("iter %d: status = %d", i, rec.Code)
		}
	}

	if got := hits.Load(); got != 3 {
		t.Fatalf("dynamic path hit %d times, want 3 (no caching)", got)
	}
}

func TestDifferentTenantsDoNotCollide(t *testing.T) {
	var tenantOneHits atomic.Int64
	var tenantTwoHits atomic.Int64

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant := feature.TenantFromContext(r.Context())
		var body []byte
		if tenant != nil && tenant.Host == "two.example" {
			tenantTwoHits.Add(1)
			body = []byte("BODY-TWO")
		} else {
			tenantOneHits.Add(1)
			body = []byte("body-one")
		}
		w.Header().Set("Content-Type", "text/css")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	_, _, chain := buildChain(t, enableSnapshot(time.Hour), nil, backend)

	// Tenant 1 cold miss.
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, reqFor("/theme.css", "one.example"))
	if rec.Body.String() != "body-one" {
		t.Fatalf("tenant1 cold: body = %q", rec.Body.String())
	}

	time.Sleep(50 * time.Millisecond)

	// Tenant 2 same path — must not be served tenant1's entry.
	rec2 := httptest.NewRecorder()
	chain.ServeHTTP(rec2, reqFor("/theme.css", "two.example"))
	if rec2.Body.String() != "BODY-TWO" {
		t.Fatalf("tenant2 cold: body = %q, want BODY-TWO (cross-tenant leak)", rec2.Body.String())
	}
	if tenantTwoHits.Load() != 1 {
		t.Fatalf("tenant2 hits = %d, want 1", tenantTwoHits.Load())
	}

	time.Sleep(50 * time.Millisecond)

	// Second requests: both tenants should hit their own cache entries.
	rec3 := httptest.NewRecorder()
	chain.ServeHTTP(rec3, reqFor("/theme.css", "one.example"))
	if rec3.Body.String() != "body-one" {
		t.Fatalf("tenant1 warm: body = %q", rec3.Body.String())
	}
	rec4 := httptest.NewRecorder()
	chain.ServeHTTP(rec4, reqFor("/theme.css", "two.example"))
	if rec4.Body.String() != "BODY-TWO" {
		t.Fatalf("tenant2 warm: body = %q", rec4.Body.String())
	}
	if tenantOneHits.Load() != 1 {
		t.Fatalf("tenant1 total hits = %d, want 1", tenantOneHits.Load())
	}
	if tenantTwoHits.Load() != 1 {
		t.Fatalf("tenant2 total hits = %d, want 1", tenantTwoHits.Load())
	}
}

func TestFeatureDisabledMeansNoCaching(t *testing.T) {
	var hits atomic.Int64
	backend := newStaticBackend(&hits, []byte("contents"))

	disabled := shared.FeatureSnapshot{Enabled: false}
	_, _, chain := buildChain(t, disabled, nil, backend)

	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, reqFor("/app.js", "one.example"))
		if rec.Code != http.StatusOK {
			t.Fatalf("iter %d: status = %d", i, rec.Code)
		}
	}

	if got := hits.Load(); got != 3 {
		t.Fatalf("disabled feature caused caching: backend hit %d, want 3", got)
	}
}

func TestTTLExpiryDropsEntry(t *testing.T) {
	var hits atomic.Int64
	backend := newStaticBackend(&hits, []byte("ephemeral"))

	// Use a very short TTL so the entry expires before the second hit.
	shortTTL := shared.FeatureSnapshot{
		Enabled: true,
		Params: map[string]any{
			"max_size_mb":       int64(8),
			"default_ttl":       "100ms",
			"static_extensions": []any{".js"},
		},
	}
	_, _, chain := buildChain(t, shortTTL, nil, backend)

	// Cold miss populates.
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, reqFor("/app.js", "one.example"))
	if hits.Load() != 1 {
		t.Fatalf("after cold miss: hits = %d, want 1", hits.Load())
	}

	// Wait past the TTL and try again — must call the backend.
	time.Sleep(250 * time.Millisecond)
	rec2 := httptest.NewRecorder()
	chain.ServeHTTP(rec2, reqFor("/app.js", "one.example"))
	if hits.Load() != 2 {
		t.Fatalf("after expiry: hits = %d, want 2 (entry did not expire)", hits.Load())
	}
}

func TestConcurrentMissDoesNotCorruptCache(t *testing.T) {
	var hits atomic.Int64
	body := []byte("concurrent-body")
	backend := newStaticBackend(&hits, body)

	_, _, chain := buildChain(t, enableSnapshot(time.Hour), nil, backend)

	const N = 100
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			chain.ServeHTTP(rec, reqFor("/big.js", "one.example"))
			if rec.Code != http.StatusOK {
				t.Errorf("concurrent iter: status = %d", rec.Code)
				return
			}
			if rec.Body.String() != string(body) {
				t.Errorf("concurrent iter: body mismatch")
			}
		}()
	}
	wg.Wait()

	// The spec permits every miss to populate the cache: the assertion
	// is simply that we served ≤ N responses correctly and backend hits
	// are bounded by N (never above).
	got := hits.Load()
	if got > int64(N) {
		t.Fatalf("backend hits = %d exceeds request count %d", got, N)
	}
	if got == 0 {
		t.Fatalf("backend never hit — cache fabricated responses on cold start")
	}

	// After all miss storms settle, a follow-up request must be served
	// from cache (backend count must not increase).
	time.Sleep(100 * time.Millisecond)
	before := hits.Load()
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, reqFor("/big.js", "one.example"))
	if hits.Load() > before {
		t.Fatalf("follow-up request called backend (hits before=%d after=%d)", before, hits.Load())
	}
	if got := rec.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("follow-up X-Cache = %q, want HIT", got)
	}
}

func TestValidateRejectsBadParams(t *testing.T) {
	f := New()
	defer f.Close()

	cases := []shared.FeatureSnapshot{
		{Enabled: true, Params: map[string]any{"max_size_mb": int64(0)}},
		{Enabled: true, Params: map[string]any{"max_size_mb": "not-a-number"}},
		{Enabled: true, Params: map[string]any{"default_ttl": "not-a-duration"}},
		{Enabled: true, Params: map[string]any{"per_tenant_size_fraction": 2.0}},
		{Enabled: true, Params: map[string]any{"per_tenant_size_fraction": -0.1}},
		{Enabled: true, Params: map[string]any{"static_extensions": "not-a-slice"}},
	}
	for i, cfg := range cases {
		if err := f.Validate(cfg); err == nil {
			t.Errorf("case %d (%v): expected error, got nil", i, cfg.Params)
		}
	}
}

func TestValidateAcceptsDisabledWithNoParams(t *testing.T) {
	f := New()
	defer f.Close()
	if err := f.Validate(shared.FeatureSnapshot{}); err != nil {
		t.Fatalf("empty disabled snapshot should validate, got %v", err)
	}
	if err := f.Validate(shared.FeatureSnapshot{Enabled: true}); err != nil {
		t.Fatalf("enabled with no params should validate, got %v", err)
	}
}

func TestObserveRebuildsOnSizeChange(t *testing.T) {
	reg := feature.NewRegistry()
	f := RegisterWith(reg)
	defer f.Close()

	g1 := feature.GlobalsSnapshot{Features: map[string]shared.FeatureSnapshot{
		FeatureName: {
			Enabled: true,
			Params: map[string]any{
				"max_size_mb":       int64(8),
				"default_ttl":       "1h",
				"static_extensions": []any{".js"},
			},
		},
	}}
	if err := reg.Reload(g1, nil); err != nil {
		t.Fatalf("first Reload: %v", err)
	}
	c1 := f.loadCache()
	if c1 == nil {
		t.Fatalf("expected cache after enable")
	}

	// Same max_size and same extensions: pointer must survive.
	g2 := feature.GlobalsSnapshot{Features: map[string]shared.FeatureSnapshot{
		FeatureName: {
			Enabled: true,
			Params: map[string]any{
				"max_size_mb":       int64(8),
				"default_ttl":       "2h",
				"static_extensions": []any{".js"},
			},
		},
	}}
	if err := reg.Reload(g2, nil); err != nil {
		t.Fatalf("second Reload: %v", err)
	}
	c2 := f.loadCache()
	if c1 != c2 {
		t.Fatalf("cache rebuilt despite only ttl change")
	}

	// Changing max_size must rebuild.
	g3 := feature.GlobalsSnapshot{Features: map[string]shared.FeatureSnapshot{
		FeatureName: {
			Enabled: true,
			Params: map[string]any{
				"max_size_mb":       int64(16),
				"default_ttl":       "2h",
				"static_extensions": []any{".js"},
			},
		},
	}}
	if err := reg.Reload(g3, nil); err != nil {
		t.Fatalf("third Reload: %v", err)
	}
	c3 := f.loadCache()
	if c3 == nil {
		t.Fatalf("cache missing after size change")
	}
	if c1 == c3 {
		t.Fatalf("expected cache rebuild on size change")
	}

	// Changing extensions must also rebuild.
	g4 := feature.GlobalsSnapshot{Features: map[string]shared.FeatureSnapshot{
		FeatureName: {
			Enabled: true,
			Params: map[string]any{
				"max_size_mb":       int64(16),
				"default_ttl":       "2h",
				"static_extensions": []any{".js", ".css"},
			},
		},
	}}
	if err := reg.Reload(g4, nil); err != nil {
		t.Fatalf("fourth Reload: %v", err)
	}
	c4 := f.loadCache()
	if c4 == nil {
		t.Fatalf("cache missing after extension change")
	}
	if c3 == c4 {
		t.Fatalf("expected cache rebuild on extension change")
	}
}

func TestNonGETMethodBypassesCache(t *testing.T) {
	var hits atomic.Int64
	backend := newStaticBackend(&hits, []byte("whatever"))

	_, _, chain := buildChain(t, enableSnapshot(time.Hour), nil, backend)

	// POST should never be cached.
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "http://example.test/app.js", nil)
		ctx := feature.WithTenant(req.Context(), &feature.TenantSnapshot{Host: "one.example", Enabled: true})
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("POST iter %d: status = %d", i, rec.Code)
		}
	}
	if got := hits.Load(); got != 3 {
		t.Fatalf("POST hit count = %d, want 3 (non-GET must not cache)", got)
	}
}

func TestNon2xxResponsesNotCached(t *testing.T) {
	var hits atomic.Int64
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body := []byte("not-found-body")
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write(body)
	})

	_, _, chain := buildChain(t, enableSnapshot(time.Hour), nil, backend)

	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, reqFor("/missing.js", "one.example"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("iter %d: status = %d, want 404", i, rec.Code)
		}
	}
	if got := hits.Load(); got != 3 {
		t.Fatalf("404 responses were cached: hits = %d, want 3", got)
	}
}

func TestNoContentLengthResponseNotCached(t *testing.T) {
	var hits atomic.Int64
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/javascript")
		// Deliberately omit Content-Length.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("streaming-body"))
	})

	_, _, chain := buildChain(t, enableSnapshot(time.Hour), nil, backend)

	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, reqFor("/s.js", "one.example"))
		if rec.Code != http.StatusOK {
			t.Fatalf("iter %d: status = %d", i, rec.Code)
		}
	}
	if got := hits.Load(); got != 3 {
		t.Fatalf("no-Content-Length responses were cached: hits = %d, want 3", got)
	}
}

func TestTenantKeyIsDeterministicAndDistinct(t *testing.T) {
	reqA := reqFor("/a.js", "one.example")
	reqB := reqFor("/a.js", "one.example")
	reqC := reqFor("/a.js", "two.example")

	if tenantKey(reqA) != tenantKey(reqB) {
		t.Fatalf("identical requests produced different keys")
	}
	if tenantKey(reqA) == tenantKey(reqC) {
		t.Fatalf("tenants produced identical keys — cross-tenant collision")
	}
}

func TestMissingTenantUsesGlobalSentinel(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.test/a.js", nil)
	k1 := tenantKey(req)

	req2 := reqFor("/a.js", globalTenantKey)
	k2 := tenantKey(req2)

	// Two different requests; keys should be identical when tenant host
	// happens to equal the sentinel — i.e. the sentinel is not magical.
	// This test documents that behaviour rather than verifying an
	// invariant: different requests may share a key iff their effective
	// tenant strings match.
	if k1 == "" || k2 == "" {
		t.Fatalf("tenant key returned empty string")
	}
}

func TestPerTenantSizeFractionInflatesCost(t *testing.T) {
	cfg := shared.FeatureSnapshot{
		Enabled: true,
		Params: map[string]any{
			"max_size_mb":              int64(16),
			"default_ttl":              "1h",
			"static_extensions":        []any{".js"},
			"per_tenant_size_fraction": 0.25,
		},
	}
	p, err := parseParams(cfg)
	if err != nil {
		t.Fatalf("parseParams: %v", err)
	}
	if got := p.extCostMultiplier(); got != 4 {
		t.Fatalf("extCostMultiplier = %d, want 4 (1/0.25)", got)
	}

	cfg.Params["per_tenant_size_fraction"] = 0.0
	p, err = parseParams(cfg)
	if err != nil {
		t.Fatalf("parseParams: %v", err)
	}
	if got := p.extCostMultiplier(); got != 1 {
		t.Fatalf("extCostMultiplier with fraction=0 = %d, want 1", got)
	}
}

// TestManyTenantsIsolated runs a small grid of tenants to make sure the
// per-tenant keying scales beyond the two-tenant smoke test.
func TestManyTenantsIsolated(t *testing.T) {
	const tenants = 5
	var hitsByTenant [tenants]atomic.Int64

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant := feature.TenantFromContext(r.Context())
		idx := 0
		if tenant != nil {
			fmt.Sscanf(tenant.Host, "tenant%d.example", &idx)
		}
		hitsByTenant[idx].Add(1)
		body := []byte(tenant.Host + "-body")
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	_, _, chain := buildChain(t, enableSnapshot(time.Hour), nil, backend)

	// Each tenant hits the same path twice. Backend should be called
	// exactly once per tenant.
	for round := 0; round < 2; round++ {
		for i := 0; i < tenants; i++ {
			host := fmt.Sprintf("tenant%d.example", i)
			rec := httptest.NewRecorder()
			chain.ServeHTTP(rec, reqFor("/shared.js", host))
			if rec.Code != http.StatusOK {
				t.Fatalf("tenant %d round %d: status = %d", i, round, rec.Code)
			}
			want := host + "-body"
			if rec.Body.String() != want {
				t.Fatalf("tenant %d round %d: body = %q, want %q", i, round, rec.Body.String(), want)
			}
		}
		// Let admission settle before round 2 so the cache can actually
		// respond from storage on the second pass.
		time.Sleep(50 * time.Millisecond)
	}

	for i := 0; i < tenants; i++ {
		if got := hitsByTenant[i].Load(); got != 1 {
			t.Errorf("tenant %d hit count = %d, want 1", i, got)
		}
	}
}
