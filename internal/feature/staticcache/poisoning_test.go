package staticcache

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"gateway/internal/feature"
)

// TestNoSessionLeakViaSetCookie is the core P0 regression test. Tenant A
// issues a request carrying a Cookie header and the backend responds
// with Set-Cookie: session=X. Tenant B then fetches the same static
// asset without cookies. The cache must not have stored A's response,
// so B must not receive Set-Cookie: session=X.
func TestNoSessionLeakViaSetCookie(t *testing.T) {
	var hits atomic.Int64
	body := []byte("console.log('ok');")

	// Backend only returns Set-Cookie for cookie-bearing requests
	// (simulating real session handling). A request without a Cookie
	// gets a "clean" response that a naive cache would happily store.
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		if r.Header.Get("Cookie") != "" {
			w.Header().Set("Set-Cookie", "session=X; Path=/; HttpOnly")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	_, _, chain := buildChain(t, enableSnapshot(time.Hour), nil, backend)

	// Tenant A — sends a cookie. Our middleware bypasses the cache, so
	// the backend replies with Set-Cookie: session=X. A naive cache
	// that dropped the Cookie-header guard would have stored this
	// response under the /static.js key (no query-string or cookie in
	// the key).
	reqA := reqFor("/static.js", "tenant-a.example")
	reqA.Header.Set("Cookie", "session=A")
	recA := httptest.NewRecorder()
	chain.ServeHTTP(recA, reqA)
	if recA.Code != http.StatusOK {
		t.Fatalf("tenant A: status = %d", recA.Code)
	}
	if got := recA.Header().Get("Set-Cookie"); got == "" {
		t.Fatalf("backend test assumption broken: tenant A should have received Set-Cookie")
	}
	// Let any async Ristretto admission drain.
	time.Sleep(50 * time.Millisecond)

	// Tenant B — no cookie. If A's response leaked into the cache,
	// B would receive Set-Cookie: session=X.
	reqB := reqFor("/static.js", "tenant-b.example")
	recB := httptest.NewRecorder()
	chain.ServeHTTP(recB, reqB)
	if recB.Code != http.StatusOK {
		t.Fatalf("tenant B: status = %d", recB.Code)
	}
	if got := recB.Header().Get("Set-Cookie"); got != "" {
		t.Fatalf("tenant B received Set-Cookie %q — cache poisoning", got)
	}
	if got := recB.Header().Get("X-Cache"); got == "HIT" {
		t.Fatalf("tenant B got cache HIT — A's entry leaked")
	}
	if hits.Load() < 2 {
		t.Fatalf("backend hits = %d, want >=2 (B should have triggered a miss of its own)", hits.Load())
	}
}

// TestQueryStringDifferentiatesCacheEntries verifies the fix to the old
// "key = path" shape: /a.css?v=1 and /a.css?v=2 must not collide.
func TestQueryStringDifferentiatesCacheEntries(t *testing.T) {
	var hits atomic.Int64

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body := []byte("body-" + r.URL.RawQuery)
		w.Header().Set("Content-Type", "text/css")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	_, _, chain := buildChain(t, enableSnapshot(time.Hour), nil, backend)

	// v=1
	req1 := httptest.NewRequest(http.MethodGet, "http://ex.test/a.css?v=1", nil)
	ctx1 := feature.WithTenant(req1.Context(), &feature.TenantSnapshot{Host: "one.example", Enabled: true})
	req1 = req1.WithContext(ctx1)
	rec1 := httptest.NewRecorder()
	chain.ServeHTTP(rec1, req1)
	if rec1.Body.String() != "body-v=1" {
		t.Fatalf("v=1: body = %q", rec1.Body.String())
	}

	time.Sleep(50 * time.Millisecond)

	// v=2 — must not reuse v=1's cached bytes.
	req2 := httptest.NewRequest(http.MethodGet, "http://ex.test/a.css?v=2", nil)
	ctx2 := feature.WithTenant(req2.Context(), &feature.TenantSnapshot{Host: "one.example", Enabled: true})
	req2 = req2.WithContext(ctx2)
	rec2 := httptest.NewRecorder()
	chain.ServeHTTP(rec2, req2)
	if rec2.Body.String() != "body-v=2" {
		t.Fatalf("v=2: body = %q (cache collision with v=1)", rec2.Body.String())
	}
	if hits.Load() != 2 {
		t.Fatalf("backend hits = %d, want 2 (each query got its own miss)", hits.Load())
	}

	// Keys for different keys must be distinct; for the same keys must match.
	// This is also a cheap safeguard independent of the end-to-end test above.
	if tenantKey(req1) == tenantKey(req2) {
		t.Fatalf("tenantKey collapsed different query strings to one key")
	}
	if tenantKey(req1) != tenantKey(req1) {
		t.Fatalf("tenantKey is nondeterministic")
	}
}

// TestQueryStringOrderIsNormalised confirms ?a=1&b=2 and ?b=2&a=1 share
// a cache slot — a cache-miss storm on reordered query params would be a
// usability bug.
func TestQueryStringOrderIsNormalised(t *testing.T) {
	var hits atomic.Int64
	body := []byte("cached")

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/css")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	_, _, chain := buildChain(t, enableSnapshot(time.Hour), nil, backend)

	for _, q := range []string{"a=1&b=2", "b=2&a=1"} {
		req := httptest.NewRequest(http.MethodGet, "http://ex.test/a.css?"+q, nil)
		ctx := feature.WithTenant(req.Context(), &feature.TenantSnapshot{Host: "one.example", Enabled: true})
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("q=%s: status=%d", q, rec.Code)
		}
		time.Sleep(20 * time.Millisecond)
	}

	if got := hits.Load(); got != 1 {
		t.Fatalf("backend hits=%d, want 1 (query order should normalise)", got)
	}
}

// TestRequestWithCookieBypassesCache confirms that cookie-bearing
// requests hit the backend every time and never read or write the cache.
func TestRequestWithCookieBypassesCache(t *testing.T) {
	var hits atomic.Int64
	body := []byte("payload")

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	_, _, chain := buildChain(t, enableSnapshot(time.Hour), nil, backend)

	for i := 0; i < 3; i++ {
		req := reqFor("/app.js", "one.example")
		req.Header.Set("Cookie", "session=abc")
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("iter %d: status=%d", i, rec.Code)
		}
		if got := rec.Header().Get("X-Cache"); got == "HIT" {
			t.Fatalf("iter %d: cookie-bearing request served from cache", i)
		}
	}
	if hits.Load() != 3 {
		t.Fatalf("backend hits=%d, want 3 (cookie must bypass cache)", hits.Load())
	}
}

// TestRequestWithAuthorizationBypassesCache mirrors the Cookie test for
// Authorization-bearing requests.
func TestRequestWithAuthorizationBypassesCache(t *testing.T) {
	var hits atomic.Int64
	body := []byte("payload")

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	_, _, chain := buildChain(t, enableSnapshot(time.Hour), nil, backend)

	for i := 0; i < 3; i++ {
		req := reqFor("/app.js", "one.example")
		req.Header.Set("Authorization", "Bearer abc")
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("iter %d: status=%d", i, rec.Code)
		}
		if got := rec.Header().Get("X-Cache"); got == "HIT" {
			t.Fatalf("iter %d: auth-bearing request served from cache", i)
		}
	}
	if hits.Load() != 3 {
		t.Fatalf("backend hits=%d, want 3 (Authorization must bypass cache)", hits.Load())
	}
}

// TestCacheControlPrivateIsNotCached confirms the response-side gating
// for Cache-Control: private.
func TestCacheControlPrivateIsNotCached(t *testing.T) {
	var hits atomic.Int64
	body := []byte("private-body")

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Header().Set("Cache-Control", "private, max-age=60")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	_, _, chain := buildChain(t, enableSnapshot(time.Hour), nil, backend)

	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, reqFor("/app.js", "one.example"))
		if rec.Code != http.StatusOK {
			t.Fatalf("iter %d: status=%d", i, rec.Code)
		}
		if rec.Body.String() != string(body) {
			t.Fatalf("iter %d: body=%q", i, rec.Body.String())
		}
	}
	if hits.Load() != 3 {
		t.Fatalf("Cache-Control: private was cached: hits=%d, want 3", hits.Load())
	}
}

// TestCacheControlNoStoreIsNotCached covers the other common directives.
func TestCacheControlNoStoreIsNotCached(t *testing.T) {
	cases := []string{"no-store", "no-cache", "must-revalidate", "s-maxage=0", "max-age=0"}
	for _, cc := range cases {
		t.Run(cc, func(t *testing.T) {
			var hits atomic.Int64
			body := []byte("body")
			backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				w.Header().Set("Content-Type", "application/javascript")
				w.Header().Set("Content-Length", strconv.Itoa(len(body)))
				w.Header().Set("Cache-Control", cc)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(body)
			})
			_, _, chain := buildChain(t, enableSnapshot(time.Hour), nil, backend)
			for i := 0; i < 3; i++ {
				rec := httptest.NewRecorder()
				chain.ServeHTTP(rec, reqFor("/app.js", "one.example"))
				if rec.Code != http.StatusOK {
					t.Fatalf("iter %d: status=%d", i, rec.Code)
				}
			}
			if hits.Load() != 3 {
				t.Fatalf("Cache-Control: %s was cached: hits=%d, want 3", cc, hits.Load())
			}
		})
	}
}

// TestVaryStarIsNotCached confirms the safe Vary handling.
func TestVaryStarIsNotCached(t *testing.T) {
	var hits atomic.Int64
	body := []byte("vary-body")

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Header().Set("Vary", "*")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	_, _, chain := buildChain(t, enableSnapshot(time.Hour), nil, backend)

	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, reqFor("/app.js", "one.example"))
		if rec.Code != http.StatusOK {
			t.Fatalf("iter %d: status=%d", i, rec.Code)
		}
	}
	if hits.Load() != 3 {
		t.Fatalf("Vary: * was cached: hits=%d, want 3", hits.Load())
	}
}

// TestSetCookieResponseIsNotCached — even without a request cookie, a
// response carrying Set-Cookie must be dropped.
func TestSetCookieResponseIsNotCached(t *testing.T) {
	var hits atomic.Int64
	body := []byte("setcookie-body")

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Header().Set("Set-Cookie", "session=X; Path=/")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	_, _, chain := buildChain(t, enableSnapshot(time.Hour), nil, backend)

	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, reqFor("/app.js", "one.example"))
		if rec.Code != http.StatusOK {
			t.Fatalf("iter %d: status=%d", i, rec.Code)
		}
	}
	if hits.Load() != 3 {
		t.Fatalf("Set-Cookie response was cached: hits=%d, want 3", hits.Load())
	}
}

// TestHTMLContentTypeNotCached ensures that even an extension-whitelisted
// request whose backend returns text/html is not stored.
func TestHTMLContentTypeNotCached(t *testing.T) {
	var hits atomic.Int64
	body := []byte("<html><body>user</body></html>")

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		// Path is whitelisted .js but server returns HTML (abusive SPA).
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	_, _, chain := buildChain(t, enableSnapshot(time.Hour), nil, backend)

	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, reqFor("/app.js", "one.example"))
		if rec.Code != http.StatusOK {
			t.Fatalf("iter %d: status=%d", i, rec.Code)
		}
	}
	if hits.Load() != 3 {
		t.Fatalf("text/html response was cached: hits=%d, want 3", hits.Load())
	}
}

// TestAcceptEncodingSegregatesEntries makes sure a gzip-encoded body
// cannot be served to a client that only accepts identity.
func TestAcceptEncodingSegregatesEntries(t *testing.T) {
	var hits atomic.Int64
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body := []byte("enc:" + r.Header.Get("Accept-Encoding"))
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	_, _, chain := buildChain(t, enableSnapshot(time.Hour), nil, backend)

	// First: gzip client.
	req1 := reqFor("/app.js", "one.example")
	req1.Header.Set("Accept-Encoding", "gzip")
	rec1 := httptest.NewRecorder()
	chain.ServeHTTP(rec1, req1)
	if rec1.Body.String() != "enc:gzip" {
		t.Fatalf("gzip: body=%q", rec1.Body.String())
	}
	time.Sleep(50 * time.Millisecond)

	// Second: identity client — must not be served gzip body.
	req2 := reqFor("/app.js", "one.example")
	// No Accept-Encoding: treated as identity.
	rec2 := httptest.NewRecorder()
	chain.ServeHTTP(rec2, req2)
	if rec2.Body.String() == "enc:gzip" {
		t.Fatalf("identity client served gzip body — encoding not segregated in cache key")
	}
}

// BenchmarkTenantKey sanity-checks that sha256 key generation stays
// cheap on the hot path.
func BenchmarkTenantKey(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "http://ex.test/app.js?a=1&b=2&c=3", nil)
	ctx := feature.WithTenant(req.Context(), &feature.TenantSnapshot{Host: "one.example", Enabled: true})
	req = req.WithContext(ctx)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tenantKey(req)
	}
}
