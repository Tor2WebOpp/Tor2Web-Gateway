package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gateway/internal/admin"
	"gateway/internal/config"
	"gateway/internal/feature"
	"gateway/internal/shared"
)

// integrationSetup wires a Server with a stub upstream and a preloaded
// tenant snapshot so tests exercise the full router + feature chain
// without spinning up a real Tor pool.
type integrationSetup struct {
	srv    *Server
	tenant string
}

// newIntegrationServer builds a Server suitable for httptest-style
// integration tests. The reverse-proxy transport is swapped out for a
// stub that returns 200 with a tenant-identifying body so tests can
// assert which tenant served a request.
func newIntegrationServer(t *testing.T, cfg *config.Config, tenants map[string]feature.TenantSnapshot, globals feature.GlobalsSnapshot) *Server {
	t.Helper()
	reg := feature.NewRegistry()

	srv, err := NewServer(cfg, nil, reg, admin.New(admin.Config{}), nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// Install tenant snapshot. This must happen after NewServer so the
	// feature registry picks up the features' observers.
	if err := reg.Reload(globals, tenants); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	// Replace the reverse proxy's upstream with a stub so tests never
	// touch a real backend. We do this by reassigning the server's
	// handler. The handler chain is assembled by NewServer with the
	// reverse proxy at the core; we swap the entire inner handler via
	// a dedicated test helper so the outer middlewares (router, gate)
	// still run.
	stubUpstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant := feature.TenantFromContext(r.Context())
		host := "unknown"
		if tenant != nil {
			host = tenant.Host
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("served:" + host))
	})

	// Rebuild the middleware stack around the stub.
	chain := reg.BuildChain(stubUpstream)
	var handler http.Handler = HostRouterFromConfig(cfg, reg, chain)
	handler = securityHeadersMiddleware(handler)
	handler = recoveryMiddleware(srv.adminGate, handler)
	srv.httpServer.Handler = handler

	return srv
}

func doGet(t *testing.T, srv *Server, host, path string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://"+host+path, nil)
	req.Host = host
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	return rr.Result()
}

func TestIntegration_MultiTenantBlocklistIsolation(t *testing.T) {
	cfg := &config.Config{
		Mode: config.ModeRemote,
		Pool: config.PoolConf{RetryAttempts: 1},
	}

	tenantA := feature.TenantSnapshot{
		Host:    "a.example",
		Enabled: true,
		Features: map[string]shared.FeatureSnapshot{
			"blocklist_regex": {
				Enabled: true,
				Params: map[string]any{
					"default_action": "404",
					"patterns": []any{
						map[string]any{
							"pattern": `(?i)wp-(login|admin)`,
							"action":  "404",
						},
					},
				},
			},
		},
	}
	tenantB := feature.TenantSnapshot{
		Host:    "b.example",
		Enabled: true,
		Features: map[string]shared.FeatureSnapshot{
			// Tenant B explicitly disables the blocklist so the same
			// path that tenant A blocks is allowed here.
			"blocklist_regex": {Enabled: false},
		},
	}
	globals := feature.GlobalsSnapshot{Features: map[string]shared.FeatureSnapshot{
		"blocklist_regex": {Enabled: true},
	}}
	tenants := map[string]feature.TenantSnapshot{
		"a.example": tenantA,
		"b.example": tenantB,
	}

	srv := newIntegrationServer(t, cfg, tenants, globals)

	// Tenant A: blocked path returns 404 from the blocklist feature.
	respA := doGet(t, srv, "a.example", "/wp-login.php")
	if respA.StatusCode != http.StatusNotFound {
		t.Errorf("tenant A blocked path: expected 404, got %d", respA.StatusCode)
	}
	_ = respA.Body.Close()

	// Tenant A: allowed path reaches the stub and is served.
	respA2 := doGet(t, srv, "a.example", "/")
	if respA2.StatusCode != http.StatusOK {
		t.Errorf("tenant A /: expected 200, got %d", respA2.StatusCode)
	}
	body, _ := io.ReadAll(respA2.Body)
	_ = respA2.Body.Close()
	if !strings.Contains(string(body), "a.example") {
		t.Errorf("expected tenant A body, got %q", body)
	}

	// Tenant B: same path is NOT blocked — blocklist disabled.
	respB := doGet(t, srv, "b.example", "/wp-login.php")
	if respB.StatusCode != http.StatusOK {
		t.Errorf("tenant B blocked path should pass: expected 200, got %d", respB.StatusCode)
	}
	bodyB, _ := io.ReadAll(respB.Body)
	_ = respB.Body.Close()
	if !strings.Contains(string(bodyB), "b.example") {
		t.Errorf("expected tenant B body, got %q", bodyB)
	}
}

func TestIntegration_UnknownHostReturns421(t *testing.T) {
	cfg := &config.Config{
		Mode: config.ModeRemote,
		Pool: config.PoolConf{RetryAttempts: 1},
	}
	globals := feature.GlobalsSnapshot{Features: map[string]shared.FeatureSnapshot{}}
	tenants := map[string]feature.TenantSnapshot{
		"known.example": {Host: "known.example", Enabled: true},
	}

	srv := newIntegrationServer(t, cfg, tenants, globals)

	resp := doGet(t, srv, "unknown.example", "/")
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Errorf("expected 421 for unknown host, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestIntegration_DisabledTenantTriggersBlockAction(t *testing.T) {
	cfg := &config.Config{
		Mode: config.ModeRemote,
		Pool: config.PoolConf{RetryAttempts: 1},
	}
	globals := feature.GlobalsSnapshot{Features: map[string]shared.FeatureSnapshot{}}
	tenants := map[string]feature.TenantSnapshot{
		"disabled.example": {Host: "disabled.example", Enabled: false},
	}

	srv := newIntegrationServer(t, cfg, tenants, globals)
	resp := doGet(t, srv, "disabled.example", "/")
	// Default block action from newRegistryLookup is 404.
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 for disabled tenant, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestIntegration_AdminGateIntercepts(t *testing.T) {
	cfg := &config.Config{
		Mode: config.ModeRemote,
		Pool: config.PoolConf{RetryAttempts: 1},
	}
	globals := feature.GlobalsSnapshot{Features: map[string]shared.FeatureSnapshot{}}
	tenants := map[string]feature.TenantSnapshot{
		"known.example": {Host: "known.example", Enabled: true},
	}

	reg := feature.NewRegistry()
	gate := admin.New(admin.Config{
		Enabled: true,
		Slug:    strings.Repeat("a", 32),
		Token1:  strings.Repeat("b", 32),
		Token2:  strings.Repeat("c", 32),
	})

	srv, err := NewServer(cfg, nil, reg, gate, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := reg.Reload(globals, tenants); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	// Matching admin path returns 501 from the gate stub.
	adminPath := "/" + strings.Repeat("a", 32) + "/" + strings.Repeat("b", 32) + "/" + strings.Repeat("c", 32)
	req := httptest.NewRequest(http.MethodGet, "http://known.example"+adminPath, nil)
	req.Host = "known.example"
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotImplemented {
		t.Errorf("admin gate: expected 501, got %d", rr.Code)
	}
}

func TestIntegration_LegacyLocalModeSynthesizesImplicitTenant(t *testing.T) {
	cfg := &config.Config{
		Mode:   config.ModeLocal,
		Domain: "legacy.example",
		Pool:   config.PoolConf{RetryAttempts: 1},
		Backends: []config.BackendConf{
			{Addr: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad.onion", Weight: 1},
		},
	}
	globals := feature.GlobalsSnapshot{Features: map[string]shared.FeatureSnapshot{}}
	// Registry intentionally empty so the implicit tenant path runs.
	srv := newIntegrationServer(t, cfg, map[string]feature.TenantSnapshot{}, globals)

	// Any host routes to the implicit tenant in local mode with
	// backends configured.
	resp := doGet(t, srv, "some.host", "/")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("legacy implicit tenant: expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(body), "legacy.example") {
		t.Errorf("expected implicit tenant body, got %q", body)
	}
}
