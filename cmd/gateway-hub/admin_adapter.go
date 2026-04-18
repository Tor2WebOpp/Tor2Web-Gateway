// admin_adapter.go provides the hub-side concrete implementations of the
// admin package's HubAccess interface. The adapter lives in the cmd
// package so the admin package never imports hub (which would create a
// cycle: hub → admin → hub).
package main

import (
	"context"

	"gateway/internal/admin"
	"gateway/internal/config"
	"gateway/internal/hub"
)

// hubAccess wires the admin router's HubAccess interface to the actual
// in-memory registries owned by gateway-hub. mirrors may be nil when the
// hub boots without P2's mirror-health subsystem; ListMirrors returns
// an empty slice in that case so the admin UI sees an empty list rather
// than a 503.
type hubAccess struct {
	reg     *hub.Registry
	mirrors *hub.MirrorRegistry
	monitor *hub.Monitor
}

// Compile-time interface assertion. The build fails fast if the admin
// HubAccess shape drifts from what hub.Registry exposes.
var _ admin.HubAccess = (*hubAccess)(nil)

// ListTenants returns a snapshot of every tenant. Order is unspecified;
// the admin UI sorts client-side.
func (a *hubAccess) ListTenants() []config.TenantConf {
	if a == nil || a.reg == nil {
		return nil
	}
	_, tenants := a.reg.Snapshot()
	out := make([]config.TenantConf, 0, len(tenants))
	for _, t := range tenants {
		out = append(out, t)
	}
	return out
}

// GetTenant returns the tenant for host or (zero, false) when missing.
func (a *hubAccess) GetTenant(host string) (config.TenantConf, bool) {
	if a == nil || a.reg == nil {
		return config.TenantConf{}, false
	}
	return a.reg.Tenant(host)
}

// UpsertTenant persists a tenant via the registry. The registry handles
// disk durability and SSE broadcast; admin only sees the success/error.
func (a *hubAccess) UpsertTenant(ctx context.Context, t config.TenantConf) error {
	if a == nil || a.reg == nil {
		return errAdapterUnwired
	}
	return a.reg.UpsertTenant(ctx, t)
}

// DeleteTenant removes a tenant by host. Same SSE/durability semantics
// as UpsertTenant.
func (a *hubAccess) DeleteTenant(ctx context.Context, host string) error {
	if a == nil || a.reg == nil {
		return errAdapterUnwired
	}
	return a.reg.DeleteTenant(ctx, host)
}

// GetGlobals returns the current globals snapshot.
func (a *hubAccess) GetGlobals() config.GlobalsConf {
	if a == nil || a.reg == nil {
		return config.GlobalsConf{}
	}
	g, _ := a.reg.Snapshot()
	return g
}

// SetGlobals persists a new globals document via the registry.
func (a *hubAccess) SetGlobals(ctx context.Context, g config.GlobalsConf) error {
	if a == nil || a.reg == nil {
		return errAdapterUnwired
	}
	return a.reg.SetGlobals(ctx, g)
}

// ListMirrors returns every known mirror health record. When the hub
// has not been initialised with the P2 mirror registry, this returns
// an empty slice so the admin UI shows "no mirrors" rather than 503.
func (a *hubAccess) ListMirrors() []hub.MirrorHealth {
	if a == nil || a.mirrors == nil {
		return nil
	}
	return a.mirrors.List()
}

// errAdapterUnwired is returned when an UpsertTenant/DeleteTenant call
// arrives at an adapter whose registry was never wired. In production
// the admin handler is only constructed after the registry is alive,
// so this only surfaces from defensive nil-guards.
var errAdapterUnwired = errAdapter{msg: "hub registry not wired"}

type errAdapter struct{ msg string }

func (e errAdapter) Error() string { return e.msg }
