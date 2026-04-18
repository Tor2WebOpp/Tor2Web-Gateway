package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gateway/internal/config"
	"gateway/internal/feature"
	"gateway/internal/shared"
)

// stubLookup lets router tests exercise specific tenant-resolution
// outcomes without spinning up a full feature.Registry + hub stack.
type stubLookup struct {
	tenants  map[string]*feature.TenantSnapshot
	implicit *feature.TenantSnapshot
	action   shared.BlockAction
	timeout  time.Duration
}

func (s *stubLookup) LookupHost(host string) *feature.TenantSnapshot {
	if t, ok := s.tenants[host]; ok {
		return t
	}
	if s.implicit != nil {
		return s.implicit
	}
	return nil
}

func (s *stubLookup) DefaultTenant() *feature.TenantSnapshot { return s.implicit }
func (s *stubLookup) BlockDefault() shared.BlockAction       { return s.action }
func (s *stubLookup) BlockTimeout() time.Duration            { return s.timeout }

// captureHandler records the tenant from context so tests can assert on
// which tenant was attached by the router.
type captureHandler struct {
	lastTenant *feature.TenantSnapshot
	called     bool
}

func (c *captureHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.called = true
	c.lastTenant = feature.TenantFromContext(r.Context())
	w.WriteHeader(http.StatusOK)
}

func TestHostRouter_MatchesHost_AttachesTenantToContext(t *testing.T) {
	tenantA := &feature.TenantSnapshot{Host: "a.example", Enabled: true}
	lookup := &stubLookup{
		tenants: map[string]*feature.TenantSnapshot{"a.example": tenantA},
		action:  shared.BlockActionNotFound,
	}
	next := &captureHandler{}

	h := hostRouterWith(lookup, next)

	req := httptest.NewRequest(http.MethodGet, "http://a.example/foo", nil)
	req.Host = "a.example:443"
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if !next.called {
		t.Fatal("expected next handler to be invoked")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if next.lastTenant == nil {
		t.Fatal("expected tenant on context, got nil")
	}
	if next.lastTenant.Host != "a.example" {
		t.Fatalf("expected host a.example, got %q", next.lastTenant.Host)
	}
}

func TestHostRouter_UnknownHost_Returns421(t *testing.T) {
	lookup := &stubLookup{
		tenants: map[string]*feature.TenantSnapshot{},
		action:  shared.BlockActionNotFound,
	}
	next := &captureHandler{}

	h := hostRouterWith(lookup, next)

	req := httptest.NewRequest(http.MethodGet, "http://unknown.example/", nil)
	req.Host = "unknown.example"
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusMisdirectedRequest {
		t.Fatalf("expected 421, got %d", rr.Code)
	}
	if next.called {
		t.Fatal("unexpected downstream call")
	}
}

func TestHostRouter_DisabledTenant_Applies404Action(t *testing.T) {
	tenant := &feature.TenantSnapshot{Host: "b.example", Enabled: false}
	lookup := &stubLookup{
		tenants: map[string]*feature.TenantSnapshot{"b.example": tenant},
		action:  shared.BlockActionNotFound,
	}
	next := &captureHandler{}

	h := hostRouterWith(lookup, next)

	req := httptest.NewRequest(http.MethodGet, "http://b.example/", nil)
	req.Host = "b.example"
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
	if next.called {
		t.Fatal("next handler should not run for disabled tenant")
	}
}

func TestHostRouter_DisabledTenant_TooManyAction(t *testing.T) {
	tenant := &feature.TenantSnapshot{Host: "c.example", Enabled: false}
	lookup := &stubLookup{
		tenants: map[string]*feature.TenantSnapshot{"c.example": tenant},
		action:  shared.BlockActionTooMany,
	}
	h := hostRouterWith(lookup, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "http://c.example/", nil)
	req.Host = "c.example"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rr.Code)
	}
}

func TestHostRouter_DisabledTenant_DropAction(t *testing.T) {
	tenant := &feature.TenantSnapshot{Host: "d.example", Enabled: false}
	lookup := &stubLookup{
		tenants: map[string]*feature.TenantSnapshot{"d.example": tenant},
		action:  shared.BlockActionDrop,
	}
	// httptest.ResponseRecorder is not a Hijacker, so drop falls back
	// to a 400 status with Content-Length: 0 per hijackOrEmpty.
	h := hostRouterWith(lookup, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "http://d.example/", nil)
	req.Host = "d.example"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 fallback for drop, got %d", rr.Code)
	}
}

func TestHostRouter_StripsPortAndLowercases(t *testing.T) {
	tenant := &feature.TenantSnapshot{Host: "mixedcase.example", Enabled: true}
	lookup := &stubLookup{
		tenants: map[string]*feature.TenantSnapshot{"mixedcase.example": tenant},
		action:  shared.BlockActionNotFound,
	}
	next := &captureHandler{}
	h := hostRouterWith(lookup, next)

	req := httptest.NewRequest(http.MethodGet, "http://mixedcase.example/", nil)
	req.Host = "MixedCase.Example:8080"
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if !next.called {
		t.Fatal("expected match after lowercasing host")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestHostRouter_ImplicitLegacyTenant_UnknownHostRoutedToDefault(t *testing.T) {
	implicit := &feature.TenantSnapshot{Host: "legacy.example", Enabled: true}
	lookup := &stubLookup{
		tenants:  map[string]*feature.TenantSnapshot{},
		implicit: implicit,
		action:   shared.BlockActionNotFound,
	}
	next := &captureHandler{}
	h := hostRouterWith(lookup, next)

	req := httptest.NewRequest(http.MethodGet, "http://whatever.example/", nil)
	req.Host = "whatever.example"
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if !next.called {
		t.Fatal("expected implicit tenant to handle request")
	}
	if next.lastTenant == nil || next.lastTenant.Host != "legacy.example" {
		t.Fatalf("expected implicit tenant attached; got %+v", next.lastTenant)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestNewRegistryLookup_SynthesizesImplicitTenantInLocalMode(t *testing.T) {
	cfg := &config.Config{
		Mode:   config.ModeLocal,
		Domain: "Legacy.Example",
		Backends: []config.BackendConf{
			{Addr: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad.onion", Weight: 1},
		},
	}
	reg := feature.NewRegistry()

	l := newRegistryLookup(cfg, reg)
	if l.implicit == nil {
		t.Fatal("expected implicit tenant in local mode with backends")
	}
	if l.implicit.Host != "legacy.example" {
		t.Fatalf("expected lowercased domain, got %q", l.implicit.Host)
	}
	if !l.implicit.Enabled {
		t.Fatal("implicit tenant must be enabled")
	}
}

func TestNewRegistryLookup_NoImplicitInRemoteMode(t *testing.T) {
	cfg := &config.Config{
		Mode:   config.ModeRemote,
		Domain: "legacy.example",
	}
	reg := feature.NewRegistry()
	l := newRegistryLookup(cfg, reg)
	if l.implicit != nil {
		t.Fatalf("remote mode must not synthesise an implicit tenant, got %+v", l.implicit)
	}
}

func TestRegistryLookup_LookupFallsBackToImplicitWhenRegistryEmpty(t *testing.T) {
	reg := feature.NewRegistry()
	// Registry has no tenants; lookup should return the implicit one.
	l := &registryLookup{
		reg: reg,
		implicit: &feature.TenantSnapshot{
			Host:    "legacy.example",
			Enabled: true,
		},
		blockAction:    func() shared.BlockAction { return shared.BlockActionNotFound },
		blockTimeoutFn: func() time.Duration { return 0 },
	}

	got := l.LookupHost("arbitrary.example")
	if got == nil || got.Host != "legacy.example" {
		t.Fatalf("expected implicit tenant, got %+v", got)
	}
}

func TestRegistryLookup_PrefersConfiguredTenantOverImplicit(t *testing.T) {
	reg := feature.NewRegistry()
	_ = reg.Reload(
		feature.GlobalsSnapshot{Features: map[string]shared.FeatureSnapshot{}},
		map[string]feature.TenantSnapshot{
			"configured.example": {Host: "configured.example", Enabled: true},
		},
	)

	l := &registryLookup{
		reg: reg,
		implicit: &feature.TenantSnapshot{
			Host:    "legacy.example",
			Enabled: true,
		},
		blockAction:    func() shared.BlockAction { return shared.BlockActionNotFound },
		blockTimeoutFn: func() time.Duration { return 0 },
	}

	got := l.LookupHost("configured.example")
	if got == nil || got.Host != "configured.example" {
		t.Fatalf("expected registered tenant, got %+v", got)
	}

	miss := l.LookupHost("unknown.example")
	if miss != nil {
		t.Fatalf("expected nil for unknown host when registry is populated, got %+v", miss)
	}
}

func TestExtractHost_EdgeCases(t *testing.T) {
	for _, tc := range []struct {
		name, host, want string
	}{
		{"empty", "", ""},
		{"no port", "example.com", "example.com"},
		{"with port", "example.com:80", "example.com"},
		{"uppercase", "EXAMPLE.COM", "example.com"},
		{"mixed case + port", "ExamplE.com:8443", "example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
			req.Host = tc.host
			if got := extractHost(req); got != tc.want {
				t.Errorf("extractHost(%q) = %q, want %q", tc.host, got, tc.want)
			}
		})
	}
}
