package feature

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"gateway/internal/shared"
)

func TestResolverTenantOverridesGlobals(t *testing.T) {
	reg := NewRegistry()
	reg.Register(newRecordingFeature("f", nil, nil))

	if err := reg.Reload(GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			"f": {Enabled: false, Version: 1},
		},
	}, map[string]TenantSnapshot{
		"host.tld": {
			Host:    "host.tld",
			Enabled: true,
			Features: map[string]shared.FeatureSnapshot{
				"f": {Enabled: true, Version: 2},
			},
		},
	}); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	resolver := &registryResolver{reg: reg}

	tenant := reg.Tenants()["host.tld"]
	req := httptest.NewRequest(http.MethodGet, "http://host.tld/", nil)
	req = req.WithContext(WithTenant(req.Context(), &tenant))

	got := resolver.Resolve(req, "f")
	if !got.Enabled || got.Version != 2 {
		t.Fatalf("tenant override not applied: got %+v", got)
	}
}

func TestResolverFallsBackToGlobals(t *testing.T) {
	reg := NewRegistry()
	reg.Register(newRecordingFeature("f", nil, nil))

	if err := reg.Reload(GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			"f": {Enabled: true, Version: 42},
		},
	}, map[string]TenantSnapshot{
		"host.tld": {
			Host:     "host.tld",
			Enabled:  true,
			Features: map[string]shared.FeatureSnapshot{}, // no "f" override
		},
	}); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	resolver := &registryResolver{reg: reg}
	tenant := reg.Tenants()["host.tld"]
	req := httptest.NewRequest(http.MethodGet, "http://host.tld/", nil)
	req = req.WithContext(WithTenant(req.Context(), &tenant))

	got := resolver.Resolve(req, "f")
	if !got.Enabled || got.Version != 42 {
		t.Fatalf("globals fallback not applied: got %+v", got)
	}
}

func TestResolverFallsBackWhenTenantAbsent(t *testing.T) {
	reg := NewRegistry()
	reg.Register(newRecordingFeature("f", nil, nil))

	if err := reg.Reload(GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			"f": {Enabled: true, Version: 7},
		},
	}, nil); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	resolver := &registryResolver{reg: reg}

	req := httptest.NewRequest(http.MethodGet, "http://anything/", nil)
	got := resolver.Resolve(req, "f")
	if !got.Enabled || got.Version != 7 {
		t.Fatalf("globals fallback not applied: got %+v", got)
	}
}

func TestResolverZeroWhenFeatureMissingEverywhere(t *testing.T) {
	reg := NewRegistry()
	// No features registered and no config reloaded.

	resolver := &registryResolver{reg: reg}
	req := httptest.NewRequest(http.MethodGet, "http://anything/", nil)

	got := resolver.Resolve(req, "does-not-exist")
	if got.Enabled || got.Version != 0 || len(got.Params) != 0 {
		t.Fatalf("expected zero FeatureSnapshot, got %+v", got)
	}
}

func TestResolverZeroWhenGlobalsMissingFeature(t *testing.T) {
	reg := NewRegistry()
	reg.Register(newRecordingFeature("known", nil, nil))

	if err := reg.Reload(GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			"known": {Enabled: true, Version: 3},
		},
	}, map[string]TenantSnapshot{
		"host.tld": {Host: "host.tld", Enabled: true},
	}); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	resolver := &registryResolver{reg: reg}
	tenant := reg.Tenants()["host.tld"]
	req := httptest.NewRequest(http.MethodGet, "http://host.tld/", nil)
	req = req.WithContext(WithTenant(req.Context(), &tenant))

	got := resolver.Resolve(req, "unknown")
	if got.Enabled || got.Version != 0 || len(got.Params) != 0 {
		t.Fatalf("expected zero snapshot for unknown feature, got %+v", got)
	}
}

func TestResolverNilRequestSafe(t *testing.T) {
	reg := NewRegistry()
	reg.Register(newRecordingFeature("f", nil, nil))
	if err := reg.Reload(GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{"f": {Enabled: true, Version: 9}},
	}, nil); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	resolver := &registryResolver{reg: reg}
	got := resolver.Resolve(nil, "f")
	if !got.Enabled || got.Version != 9 {
		t.Fatalf("resolver with nil request should still read globals: got %+v", got)
	}
}

func TestWithTenantAndTenantFromContext(t *testing.T) {
	t.Run("nil context returns nil", func(t *testing.T) {
		if got := TenantFromContext(nil); got != nil {
			t.Fatalf("TenantFromContext(nil) = %+v, want nil", got)
		}
	})

	t.Run("absent key returns nil", func(t *testing.T) {
		if got := TenantFromContext(context.Background()); got != nil {
			t.Fatalf("TenantFromContext(Background) = %+v, want nil", got)
		}
	})

	t.Run("round-trip", func(t *testing.T) {
		ts := &TenantSnapshot{Host: "example.tld", Enabled: true}
		ctx := WithTenant(context.Background(), ts)
		got := TenantFromContext(ctx)
		if got == nil {
			t.Fatalf("TenantFromContext after WithTenant = nil")
		}
		if got.Host != ts.Host || got.Enabled != ts.Enabled {
			t.Fatalf("TenantFromContext = %+v, want %+v", got, ts)
		}
	})

	t.Run("nil tenant stored and returned", func(t *testing.T) {
		ctx := WithTenant(context.Background(), nil)
		if got := TenantFromContext(ctx); got != nil {
			t.Fatalf("stored nil tenant should read back as nil, got %+v", got)
		}
	})
}

// TestResolverConcurrentWithReload ensures resolver reads stay race-free
// while Reload mutates the snapshot.
func TestResolverConcurrentWithReload(t *testing.T) {
	reg := NewRegistry()
	reg.Register(newRecordingFeature("f", nil, nil))

	if err := reg.Reload(GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{"f": {Enabled: true, Version: 0}},
	}, nil); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	resolver := &registryResolver{reg: reg}

	var (
		wg       sync.WaitGroup
		stop     atomic.Bool
		readErrs atomic.Int64
	)

	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
				req = req.WithContext(WithTenant(req.Context(), &TenantSnapshot{
					Host:     "x",
					Enabled:  true,
					Features: map[string]shared.FeatureSnapshot{"f": {Enabled: true, Version: 999}},
				}))
				got := resolver.Resolve(req, "f")
				if !got.Enabled {
					readErrs.Add(1)
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer stop.Store(true)
		for i := 0; i < 200; i++ {
			g := GlobalsSnapshot{Features: map[string]shared.FeatureSnapshot{
				"f": {Enabled: i%2 == 0, Version: uint64(i)},
			}}
			if err := reg.Reload(g, nil); err != nil {
				t.Errorf("Reload: %v", err)
			}
		}
	}()

	wg.Wait()

	if readErrs.Load() != 0 {
		t.Fatalf("observed %d unexpected disabled reads with tenant override", readErrs.Load())
	}
}
