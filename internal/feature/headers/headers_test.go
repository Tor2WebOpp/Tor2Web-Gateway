package headers

import (
	"fmt"
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

// okInner returns a simple handler that writes back a 200 with an empty
// body and sets two baseline response headers so strip_downstream tests
// have something to remove.
func okInner() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "test-server/1.0")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("X-From-Backend", "yes")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

// buildChain wires a Feature+Registry combo around the given inner
// handler. It enables the feature globally and installs the supplied
// params on the globals snapshot; callers can override per-tenant via
// the returned registry.
func buildChain(t *testing.T, params map[string]any, tenants map[string]feature.TenantSnapshot) (http.Handler, *feature.Registry, *Feature) {
	t.Helper()
	reg := feature.NewRegistry()
	f := RegisterWith(reg)

	globals := feature.GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: {Enabled: true, Params: params, Version: 1},
		},
	}
	if err := reg.Reload(globals, tenants); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	chain := reg.BuildChain(okInner())
	return chain, reg, f
}

// withTenant returns r wrapped in a context that names a tenant with the
// given host. It's used to exercise the tenant-aware branches of the
// middleware.
func withTenant(r *http.Request, host string, features map[string]shared.FeatureSnapshot) *http.Request {
	return r.WithContext(feature.WithTenant(r.Context(), &feature.TenantSnapshot{
		Host:     host,
		Enabled:  true,
		Features: features,
	}))
}

func TestStripUpstreamRemovesListedRequestHeaders(t *testing.T) {
	// Inner handler captures the request it saw so we can assert the
	// upstream strip actually ran before forward.
	var seen http.Header
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	})

	reg := feature.NewRegistry()
	RegisterWith(reg)
	err := reg.Reload(feature.GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: {Enabled: true, Params: map[string]any{
				"strip_upstream": []any{"Server", "X-Powered-By", "Via"},
			}},
		},
	}, nil)
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	chain := reg.BuildChain(inner)

	req := httptest.NewRequest(http.MethodGet, "http://example.tld/", nil)
	req.Header.Set("Server", "oops")
	req.Header.Set("X-Powered-By", "php")
	req.Header.Set("Via", "1.1 gateway")
	req.Header.Set("X-Should-Keep", "yes")

	chain.ServeHTTP(httptest.NewRecorder(), req)

	if got := seen.Get("Server"); got != "" {
		t.Errorf("Server header should be stripped, got %q", got)
	}
	if got := seen.Get("X-Powered-By"); got != "" {
		t.Errorf("X-Powered-By header should be stripped, got %q", got)
	}
	if got := seen.Get("Via"); got != "" {
		t.Errorf("Via header should be stripped, got %q", got)
	}
	if got := seen.Get("X-Should-Keep"); got != "yes" {
		t.Errorf("X-Should-Keep unexpectedly changed: %q", got)
	}
}

func TestAddUpstreamAddsHeadersAndClientIPTemplateExpands(t *testing.T) {
	var seen http.Header
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	})

	reg := feature.NewRegistry()
	RegisterWith(reg)
	err := reg.Reload(feature.GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: {Enabled: true, Params: map[string]any{
				"add_upstream": []any{
					map[string]any{"name": "X-Forwarded-For", "value": "{{client_ip}}"},
					map[string]any{"name": "X-Forwarded-Proto", "value": "https"},
					map[string]any{"name": "X-Tenant", "value": "{{tenant_host}}"},
				},
			}},
		},
	}, nil)
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	chain := reg.BuildChain(inner)

	req := httptest.NewRequest(http.MethodGet, "http://example.tld/", nil)
	req.RemoteAddr = "203.0.113.7:54321"
	req = withTenant(req, "example.tld", nil)

	chain.ServeHTTP(httptest.NewRecorder(), req)

	if got := seen.Get("X-Forwarded-For"); got != "203.0.113.7" {
		t.Errorf("X-Forwarded-For = %q, want %q", got, "203.0.113.7")
	}
	if got := seen.Get("X-Forwarded-Proto"); got != "https" {
		t.Errorf("X-Forwarded-Proto = %q, want %q", got, "https")
	}
	if got := seen.Get("X-Tenant"); got != "example.tld" {
		t.Errorf("X-Tenant = %q, want %q", got, "example.tld")
	}
}

func TestStripDownstreamRemovesResponseHeaders(t *testing.T) {
	chain, _, _ := buildChain(t, map[string]any{
		"strip_downstream": []any{"Content-Security-Policy", "Server"},
	}, nil)

	req := httptest.NewRequest(http.MethodGet, "http://example.tld/", nil)
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)

	if got := rec.Header().Get("Content-Security-Policy"); got != "" {
		t.Errorf("Content-Security-Policy should be stripped, got %q", got)
	}
	if got := rec.Header().Get("Server"); got != "" {
		t.Errorf("Server should be stripped, got %q", got)
	}
	if got := rec.Header().Get("X-From-Backend"); got != "yes" {
		t.Errorf("X-From-Backend unexpectedly changed: %q", got)
	}
}

func TestAddDownstreamRequestIDDiffersAcrossRequests(t *testing.T) {
	chain, _, _ := buildChain(t, map[string]any{
		"add_downstream": []any{
			map[string]any{"name": "X-Request-ID", "value": "{{request_id}}"},
		},
	}, nil)

	seen := make(map[string]struct{}, 50)
	for i := 0; i < 50; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://example.tld/", nil)
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)
		id := rec.Header().Get("X-Request-ID")
		if id == "" {
			t.Fatalf("iteration %d: empty X-Request-ID", i)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("iteration %d: duplicate request id %q", i, id)
		}
		seen[id] = struct{}{}
	}
}

func TestTenantOverrideWins(t *testing.T) {
	// Globals strip Server and set X-Role=global; tenant override
	// strips X-Powered-By and sets X-Role=tenant. With the tenant
	// bound to the request, only the tenant rules must apply.
	var seenReq http.Header
	reg := feature.NewRegistry()
	RegisterWith(reg)
	err := reg.Reload(feature.GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: {Enabled: true, Params: map[string]any{
				"strip_upstream": []any{"Server"},
				"add_upstream": []any{
					map[string]any{"name": "X-Role", "value": "global"},
				},
			}},
		},
	}, map[string]feature.TenantSnapshot{
		"tenant-a.tld": {
			Host:    "tenant-a.tld",
			Enabled: true,
			Features: map[string]shared.FeatureSnapshot{
				FeatureName: {Enabled: true, Params: map[string]any{
					"strip_upstream": []any{"X-Powered-By"},
					"add_upstream": []any{
						map[string]any{"name": "X-Role", "value": "tenant"},
					},
				}},
			},
		},
	})
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenReq = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	})
	chain := reg.BuildChain(inner)

	req := httptest.NewRequest(http.MethodGet, "http://tenant-a.tld/", nil)
	req.Header.Set("Server", "should-survive-because-globals-are-not-used")
	req.Header.Set("X-Powered-By", "should-be-stripped-by-tenant-rules")
	req = withTenant(req, "tenant-a.tld", map[string]shared.FeatureSnapshot{
		FeatureName: {Enabled: true, Params: map[string]any{
			"strip_upstream": []any{"X-Powered-By"},
			"add_upstream": []any{
				map[string]any{"name": "X-Role", "value": "tenant"},
			},
		}},
	})

	chain.ServeHTTP(httptest.NewRecorder(), req)

	if got := seenReq.Get("X-Powered-By"); got != "" {
		t.Errorf("tenant rules should have stripped X-Powered-By, got %q", got)
	}
	if got := seenReq.Get("Server"); got == "" {
		t.Errorf("tenant rules should NOT strip Server (that's a globals-only rule), but it was removed")
	}
	if got := seenReq.Get("X-Role"); got != "tenant" {
		t.Errorf("X-Role = %q, want %q (tenant override must win)", got, "tenant")
	}
}

func TestTemplateParseErrorSurfacesInValidate(t *testing.T) {
	f := New()

	// Known variable — must validate.
	okCfg := shared.FeatureSnapshot{Enabled: true, Version: 1, Params: map[string]any{
		"add_upstream": []any{
			map[string]any{"name": "X-Real-IP", "value": "{{client_ip}}"},
		},
	}}
	if err := f.Validate(okCfg); err != nil {
		t.Fatalf("expected ok cfg to validate, got %v", err)
	}

	// Unknown variable — must fail.
	badCfg := shared.FeatureSnapshot{Enabled: true, Params: map[string]any{
		"add_downstream": []any{
			map[string]any{"name": "X-Foo", "value": "{{nope}}"},
		},
	}}
	if err := f.Validate(badCfg); err == nil {
		t.Fatalf("expected validate error for unknown variable")
	}

	// Unterminated variable — must fail.
	unterm := shared.FeatureSnapshot{Enabled: true, Params: map[string]any{
		"add_upstream": []any{
			map[string]any{"name": "X-Bad", "value": "prefix {{client_ip"},
		},
	}}
	if err := f.Validate(unterm); err == nil {
		t.Fatalf("expected validate error for unterminated variable")
	}

	// Registry-level Reload must also refuse bad configs without
	// corrupting the current snapshot.
	reg := feature.NewRegistry()
	RegisterWith(reg)
	if err := reg.Reload(feature.GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{FeatureName: okCfg},
	}, nil); err != nil {
		t.Fatalf("baseline Reload: %v", err)
	}
	if err := reg.Reload(feature.GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{FeatureName: badCfg},
	}, nil); err == nil {
		t.Fatalf("expected Reload to fail on bad template")
	}
	// The baseline snapshot must remain live.
	if v := reg.Globals().Features[FeatureName].Version; v != 1 {
		t.Errorf("expected baseline version 1 to be preserved, got %d", v)
	}
}

func TestTemplateParseAllVariables(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want string
	}{
		{"empty", "", ""},
		{"literal", "hello", "hello"},
		{"client_ip", "{{client_ip}}", "1.2.3.4"},
		{"tenant_host", "{{tenant_host}}", "example.tld"},
		{"header_lookup", "{{header:X-Custom}}", "hi"},
		{"mixed", "ip={{client_ip}};host={{tenant_host}};h={{header:X-Custom}}", "ip=1.2.3.4;host=example.tld;h=hi"},
		{"adjacent", "{{client_ip}}{{tenant_host}}", "1.2.3.4example.tld"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tpl, err := Parse(tc.s)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.s, err)
			}
			req := httptest.NewRequest(http.MethodGet, "http://example.tld/", nil)
			req.Header.Set("X-Custom", "hi")
			got := tpl.Render(RenderCtx{
				ClientIP:   "1.2.3.4",
				TenantHost: "example.tld",
				Req:        req,
				Now:        time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
			})
			if got != tc.want {
				t.Errorf("Render(%q) = %q, want %q", tc.s, got, tc.want)
			}
		})
	}
}

func TestTemplateNowRFC3339(t *testing.T) {
	tpl, err := Parse("ts={{now_rfc3339}}")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	now := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	got := tpl.Render(RenderCtx{Now: now})
	want := "ts=2024-01-02T03:04:05Z"
	if got != want {
		t.Errorf("Render = %q, want %q", got, want)
	}

	// Zero-time path must not blow up — it should substitute time.Now.
	got2 := tpl.Render(RenderCtx{})
	if !strings.HasPrefix(got2, "ts=20") {
		t.Errorf("zero-time Render = %q, want RFC3339-looking", got2)
	}
}

func TestTemplateParseErrors(t *testing.T) {
	cases := []string{
		"{{}}",
		"{{   }}",
		"prefix {{client_ip",
		"{{unknown}}",
		"{{header:}}",
	}
	for _, s := range cases {
		if _, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) expected error, got nil", s)
		}
	}
}

func TestIPv6ClientIPExtraction(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.tld/", nil)
	req.RemoteAddr = "[2001:db8::1]:12345"
	got := clientIP(req)
	if got != "2001:db8::1" {
		t.Errorf("clientIP = %q, want %q", got, "2001:db8::1")
	}

	req.RemoteAddr = "203.0.113.7:80"
	if got := clientIP(req); got != "203.0.113.7" {
		t.Errorf("clientIP = %q, want %q", got, "203.0.113.7")
	}

	req.RemoteAddr = ""
	if got := clientIP(req); got != "" {
		t.Errorf("clientIP = %q, want empty", got)
	}
}

func TestDisabledFeatureIsPassThrough(t *testing.T) {
	reg := feature.NewRegistry()
	RegisterWith(reg)
	// Snapshot with params but Enabled=false — middleware must not act.
	if err := reg.Reload(feature.GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: {Enabled: false, Params: map[string]any{
				"strip_upstream": []any{"Server"},
			}},
		},
	}, nil); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	var seen http.Header
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	})
	chain := reg.BuildChain(inner)

	req := httptest.NewRequest(http.MethodGet, "http://example.tld/", nil)
	req.Header.Set("Server", "keep-me")
	chain.ServeHTTP(httptest.NewRecorder(), req)

	if got := seen.Get("Server"); got != "keep-me" {
		t.Errorf("feature disabled must be pass-through; Server = %q", got)
	}
}

func TestConcurrentReloadAndRequests(t *testing.T) {
	reg := feature.NewRegistry()
	RegisterWith(reg)

	// Start with a rich but valid configuration.
	initial := feature.GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: {Enabled: true, Params: map[string]any{
				"strip_upstream": []any{"Server", "X-Powered-By"},
				"add_upstream": []any{
					map[string]any{"name": "X-Forwarded-For", "value": "{{client_ip}}"},
				},
				"strip_downstream": []any{"Content-Security-Policy"},
				"add_downstream": []any{
					map[string]any{"name": "X-Request-ID", "value": "{{request_id}}"},
				},
			}, Version: 1},
		},
	}
	if err := reg.Reload(initial, nil); err != nil {
		t.Fatalf("initial Reload: %v", err)
	}
	chain := reg.BuildChain(okInner())

	var (
		wg          sync.WaitGroup
		stop        atomic.Bool
		reloads     atomic.Int64
		requests    atomic.Int64
		requestErrs atomic.Int64
	)

	// 32 request goroutines.
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for !stop.Load() {
				req := httptest.NewRequest(http.MethodGet, "http://example.tld/", nil)
				req.RemoteAddr = fmt.Sprintf("192.0.2.%d:10000", (id%254)+1)
				req.Header.Set("Server", "to-be-stripped")
				tenant := "example.tld"
				if id%2 == 0 {
					tenant = "other.tld"
				}
				req = withTenant(req, tenant, nil)

				rec := httptest.NewRecorder()
				func() {
					defer func() {
						if r := recover(); r != nil {
							requestErrs.Add(1)
						}
					}()
					chain.ServeHTTP(rec, req)
				}()
				if rec.Code != http.StatusOK {
					requestErrs.Add(1)
				}
				requests.Add(1)
			}
		}(g)
	}

	// Reload driver: flip between two valid snapshots.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer stop.Store(true)
		for i := 0; i < 200; i++ {
			params := map[string]any{
				"strip_upstream": []any{"Server", "X-Powered-By"},
				"add_upstream": []any{
					map[string]any{"name": "X-Forwarded-For", "value": "{{client_ip}}"},
				},
				"add_downstream": []any{
					map[string]any{"name": "X-Request-ID", "value": "{{request_id}}"},
				},
			}
			if i%2 == 1 {
				params["add_upstream"] = []any{
					map[string]any{"name": "X-Tenant", "value": "{{tenant_host}}"},
					map[string]any{"name": "X-Now", "value": "{{now_rfc3339}}"},
				}
			}
			g := feature.GlobalsSnapshot{
				Features: map[string]shared.FeatureSnapshot{
					FeatureName: {Enabled: true, Params: params, Version: uint64(i + 2)},
				},
			}
			if err := reg.Reload(g, nil); err != nil {
				t.Errorf("Reload %d: %v", i, err)
				return
			}
			reloads.Add(1)
		}
	}()

	wg.Wait()

	if requestErrs.Load() != 0 {
		t.Fatalf("request goroutines saw %d errors/panics", requestErrs.Load())
	}
	if reloads.Load() != 200 {
		t.Fatalf("expected 200 reloads, got %d", reloads.Load())
	}
	if requests.Load() == 0 {
		t.Fatalf("no requests ran during concurrency test")
	}
}

func TestHeaderTemplateReadsRequestHeader(t *testing.T) {
	var seen http.Header
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	})

	reg := feature.NewRegistry()
	RegisterWith(reg)
	if err := reg.Reload(feature.GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: {Enabled: true, Params: map[string]any{
				"add_upstream": []any{
					map[string]any{"name": "X-User-Agent-Copy", "value": "{{header:User-Agent}}"},
				},
			}},
		},
	}, nil); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	chain := reg.BuildChain(inner)

	req := httptest.NewRequest(http.MethodGet, "http://example.tld/", nil)
	req.Header.Set("User-Agent", "MyTestAgent/1.0")

	chain.ServeHTTP(httptest.NewRecorder(), req)

	if got := seen.Get("X-User-Agent-Copy"); got != "MyTestAgent/1.0" {
		t.Errorf("X-User-Agent-Copy = %q, want %q", got, "MyTestAgent/1.0")
	}
}

func TestAbsentRulesPassesThrough(t *testing.T) {
	// Enabled globally but with no lists configured — should still be
	// a no-op and not corrupt the request or response.
	chain, _, _ := buildChain(t, map[string]any{}, nil)

	req := httptest.NewRequest(http.MethodGet, "http://example.tld/", nil)
	req.Header.Set("Server", "keep-me")
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if rec.Header().Get("X-From-Backend") != "yes" {
		t.Errorf("response header from inner handler missing")
	}
}

func TestInvalidAddListShape(t *testing.T) {
	f := New()
	cases := []shared.FeatureSnapshot{
		// add_upstream is not a list
		{Enabled: true, Params: map[string]any{"add_upstream": "not a list"}},
		// missing name
		{Enabled: true, Params: map[string]any{
			"add_upstream": []any{map[string]any{"value": "x"}},
		}},
		// empty name
		{Enabled: true, Params: map[string]any{
			"add_upstream": []any{map[string]any{"name": "   ", "value": "x"}},
		}},
		// missing value
		{Enabled: true, Params: map[string]any{
			"add_upstream": []any{map[string]any{"name": "X"}},
		}},
		// strip list wrong shape
		{Enabled: true, Params: map[string]any{"strip_upstream": "not a list"}},
		// strip list empty name
		{Enabled: true, Params: map[string]any{"strip_upstream": []any{""}}},
	}
	for i, c := range cases {
		if err := f.Validate(c); err == nil {
			t.Errorf("case %d: expected Validate error", i)
		}
	}
}
