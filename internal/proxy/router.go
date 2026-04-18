package proxy

import (
	"net/http"
	"strings"
	"time"

	"gateway/internal/config"
	"gateway/internal/feature"
	"gateway/internal/shared"
)

// defaultImplicitTenantHost is the host attached to the synthesized
// "default" tenant in legacy single-tenant local mode. It keeps
// feature.TenantFromContext non-nil so per-tenant keying (rate limit,
// negative cache, etc.) still behaves deterministically.
const defaultImplicitTenantHost = "default"

// hostLookup resolves a lowercased host to the tenant snapshot that
// should handle the request. Implementations must be safe for concurrent
// use and are expected to return nil when no tenant matches.
type hostLookup interface {
	LookupHost(host string) *feature.TenantSnapshot
	DefaultTenant() *feature.TenantSnapshot
	BlockDefault() shared.BlockAction
	BlockTimeout() time.Duration
}

// registryLookup adapts a *feature.Registry + a function returning the
// current globals block-response configuration to the hostLookup
// interface used by HostRouter.
type registryLookup struct {
	reg            *feature.Registry
	implicit       *feature.TenantSnapshot
	blockAction    func() shared.BlockAction
	blockTimeoutFn func() time.Duration
}

// LookupHost performs an atomic tenant lookup against the registry's
// current snapshot. It falls back to the implicit tenant (legacy local
// mode) if the registry has no tenants at all, which preserves the
// single-domain deployment contract of wave 1.
func (l *registryLookup) LookupHost(host string) *feature.TenantSnapshot {
	tenants := l.reg.Tenants()
	// Legacy single-tenant mode: the registry has no tenants, so every
	// host maps to the implicit "default" tenant. This mirrors the
	// pre-P1 behaviour where the proxy served cfg.Domain for any incoming
	// Host header.
	if len(tenants) == 0 && l.implicit != nil {
		return l.implicit
	}
	if t, ok := tenants[host]; ok {
		tCopy := t
		return &tCopy
	}
	return nil
}

// DefaultTenant returns the implicit tenant (if any). Used by callers
// that need to know whether legacy mode is active.
func (l *registryLookup) DefaultTenant() *feature.TenantSnapshot {
	return l.implicit
}

// BlockDefault returns the globally configured default block action for
// requests denied by the router (e.g. tenant disabled).
func (l *registryLookup) BlockDefault() shared.BlockAction {
	if l.blockAction == nil {
		return shared.BlockActionNotFound
	}
	a := l.blockAction()
	if !a.IsValid() {
		return shared.BlockActionNotFound
	}
	return a
}

// BlockTimeout returns the configured "timeout" sleep for the timeout
// block action. Zero falls back to 30 seconds at the response site.
func (l *registryLookup) BlockTimeout() time.Duration {
	if l.blockTimeoutFn == nil {
		return 0
	}
	return l.blockTimeoutFn()
}

// newRegistryLookup wires a registryLookup over cfg + the registry. The
// implicit tenant is synthesised only in legacy local mode, defined as
// "cfg.Mode == local AND cfg.Backends is populated". It inherits the
// legacy domain as its host so downstream features see a stable key.
func newRegistryLookup(cfg *config.Config, reg *feature.Registry) *registryLookup {
	l := &registryLookup{reg: reg}

	if cfg != nil && cfg.Mode == config.ModeLocal && len(cfg.Backends) > 0 {
		host := defaultImplicitTenantHost
		if cfg.Domain != "" {
			host = strings.ToLower(cfg.Domain)
		}
		l.implicit = &feature.TenantSnapshot{
			Host:     host,
			Enabled:  true,
			Features: map[string]shared.FeatureSnapshot{},
		}
	}

	// Block-response defaults come from the runtime globals when wired,
	// but fall back to Block404 during bootstrap when no globals have
	// been loaded yet. The closure captures the registry so late Reload
	// calls see the new value without rebuilding the lookup.
	l.blockAction = func() shared.BlockAction {
		// The registry does not itself model block_response; wave-3
		// wiring (snapshot.go) pushes it into a feature-specific key.
		// Until then, default to 404 which is the safest public-facing
		// choice for an unknown host.
		return shared.BlockActionNotFound
	}
	l.blockTimeoutFn = func() time.Duration { return 0 }

	return l
}

// HostRouter returns middleware that extracts the Host header, resolves
// it against the registry's current tenant map, and either:
//   - attaches the TenantSnapshot to the request context and invokes
//     next;
//   - returns 421 Misdirected Request when the host is unknown;
//   - invokes the configured block action when the tenant is disabled.
//
// In legacy local mode (no tenants in the registry, but cfg has a
// non-empty Backends list) every request is routed to a synthesised
// "default" tenant so downstream middlewares observe a stable tenant
// context.
func HostRouter(reg *feature.Registry, next http.Handler) http.Handler {
	l := &registryLookup{reg: reg}
	return hostRouterWith(l, next)
}

// HostRouterFromConfig is the production constructor that preserves
// backward compatibility with legacy single-tenant deployments by
// synthesising an implicit default tenant when cfg indicates local mode.
func HostRouterFromConfig(cfg *config.Config, reg *feature.Registry, next http.Handler) http.Handler {
	return hostRouterWith(newRegistryLookup(cfg, reg), next)
}

// hostRouterWith is the internal plumbing shared by the two public
// constructors. Kept package-private so tests can inject a deterministic
// hostLookup without reaching into the registry.
func hostRouterWith(l hostLookup, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := extractHost(r)

		tenant := l.LookupHost(host)
		if tenant == nil {
			// 421 Misdirected Request signals to the client that the
			// certificate/connection is valid but the destination was
			// wrong — explicitly distinct from 404, which a tenant path
			// could also produce on its own.
			w.Header().Set("Content-Length", "0")
			w.WriteHeader(http.StatusMisdirectedRequest)
			return
		}

		if !tenant.Enabled {
			applyBlockAction(w, r, l.BlockDefault(), l.BlockTimeout())
			return
		}

		ctx := feature.WithTenant(r.Context(), tenant)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// extractHost strips any port from r.Host and lowercases the remainder.
// An empty Host header is returned as "" so callers can short-circuit.
func extractHost(r *http.Request) string {
	if r.Host == "" {
		return ""
	}
	h := r.Host
	if idx := strings.IndexByte(h, ':'); idx >= 0 {
		h = h[:idx]
	}
	return strings.ToLower(h)
}

// applyBlockAction terminates the request according to action. It
// mirrors the shape used by feature.blocklist so behaviour is consistent
// across the router and the blocklist middleware.
func applyBlockAction(w http.ResponseWriter, r *http.Request, action shared.BlockAction, timeout time.Duration) {
	switch action {
	case shared.BlockActionNotFound:
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusNotFound)
	case shared.BlockActionTooMany:
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	case shared.BlockActionTimeout:
		sleep := timeout
		if sleep <= 0 {
			sleep = 30 * time.Second
		}
		ctx := r.Context()
		t := time.NewTimer(sleep)
		defer t.Stop()
		select {
		case <-t.C:
		case <-ctx.Done():
		}
		hijackOrEmpty(w, http.StatusGatewayTimeout)
	case shared.BlockActionDrop:
		hijackOrEmpty(w, 0)
	default:
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusNotFound)
	}
}

// hijackOrEmpty closes the underlying TCP connection when the writer
// supports hijacking; otherwise writes fallbackCode with an empty body.
// When fallbackCode is 0 the fallback writes 400 (Bad Request) to
// mirror feature.blocklist.hijackAndClose.
func hijackOrEmpty(w http.ResponseWriter, fallbackCode int) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		code := fallbackCode
		if code == 0 {
			code = http.StatusBadRequest
		}
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(code)
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		code := fallbackCode
		if code == 0 {
			code = http.StatusBadRequest
		}
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(code)
		return
	}
	_ = conn.Close()
}
