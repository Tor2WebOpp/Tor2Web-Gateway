package ttlblock

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gateway/internal/feature"
	"gateway/internal/shared"
)

// FeatureName is the registry identifier for the TTL blocklist feature.
const FeatureName = "ttl_blocklist"

// defaultSweepInterval is how often the background sweeper runs. The
// feature's Start method launches one sweeper per live store.
const defaultSweepInterval = 10 * time.Minute

// Params is the typed view of a FeatureSnapshot.Params map. Fields are
// deliberately tolerant: missing, zero-valued, or wrong-typed values
// fall back to safe defaults rather than rejecting the snapshot, so an
// operator who omits an optional field does not tear down the feature.
type Params struct {
	DBPath       string
	DefaultTTL   time.Duration
	Action       shared.BlockAction
	SaltedHashes bool
	SaltFile     string
	MaxEntries   int
	TrustXFF     bool
}

// parseParams materialises a Params from the raw snapshot map. Unknown
// or malformed fields fall back to the package defaults.
func parseParams(p map[string]any) Params {
	out := Params{
		DBPath:       "/var/lib/gateway/ttlblock.db",
		DefaultTTL:   24 * time.Hour,
		Action:       shared.BlockActionDrop,
		SaltedHashes: true,
		SaltFile:     "/etc/gateway/ttlblock-salt",
		MaxEntries:   100000,
		TrustXFF:     false,
	}
	if p == nil {
		return out
	}
	if v, ok := p["db_path"].(string); ok && v != "" {
		out.DBPath = v
	}
	if v, ok := p["default_ttl"].(string); ok && v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			out.DefaultTTL = d
		}
	}
	if v, ok := p["action"].(string); ok && v != "" {
		a := shared.BlockAction(v)
		if a.IsValid() {
			out.Action = a
		}
	}
	if v, ok := p["salted_hashes"].(bool); ok {
		out.SaltedHashes = v
	}
	if v, ok := p["salt_file"].(string); ok {
		out.SaltFile = v
	}
	if v, ok := p["max_entries"]; ok {
		switch n := v.(type) {
		case int:
			out.MaxEntries = n
		case int64:
			out.MaxEntries = int(n)
		case float64:
			out.MaxEntries = int(n)
		}
	}
	if v, ok := p["trust_xff"].(bool); ok {
		out.TrustXFF = v
	}
	return out
}

// Feature is the ttl_blocklist implementation of the feature.Feature
// interface. One instance is registered per Registry.
type Feature struct {
	enabled atomic.Bool

	mu        sync.RWMutex
	store     *Store
	globalCfg Params
	tenantCfg map[string]Params

	// sweeper lifecycle.
	sweepMu       sync.Mutex
	sweeperCancel context.CancelFunc
	sweeperDone   chan struct{}
	sweepInterval time.Duration

	// openStore is injected by tests to substitute a pre-built store
	// (e.g. with an in-memory file under t.TempDir()). Production
	// initialisation flows through the default OpenStore.
	openStore func(path, saltFile string) (*Store, error)
}

// New constructs a fresh Feature ready for registration. Callers may
// override the sweep interval by assigning to SweepInterval before
// calling Start.
func New() *Feature {
	return &Feature{
		tenantCfg:     map[string]Params{},
		sweepInterval: defaultSweepInterval,
		openStore:     OpenStore,
	}
}

// Name returns the registry identifier.
func (f *Feature) Name() string { return FeatureName }

// Validate inspects a snapshot and returns an error only when a
// supplied field is obviously wrong. Missing fields are accepted — the
// defaults in parseParams will fill them in.
func (f *Feature) Validate(cfg shared.FeatureSnapshot) error {
	if !cfg.Enabled {
		return nil
	}
	if cfg.Params == nil {
		return nil
	}
	if v, ok := cfg.Params["default_ttl"].(string); ok && v != "" {
		if _, err := time.ParseDuration(v); err != nil {
			return fmt.Errorf("default_ttl: %w", err)
		}
	}
	if v, ok := cfg.Params["action"].(string); ok && v != "" {
		if !shared.BlockAction(v).IsValid() {
			return fmt.Errorf("action %q is not one of drop|404|429|timeout", v)
		}
	}
	if v, ok := cfg.Params["max_entries"]; ok {
		switch n := v.(type) {
		case int:
			if n < 0 {
				return fmt.Errorf("max_entries must be non-negative, got %d", n)
			}
		case int64:
			if n < 0 {
				return fmt.Errorf("max_entries must be non-negative, got %d", n)
			}
		case float64:
			if n < 0 {
				return fmt.Errorf("max_entries must be non-negative, got %v", n)
			}
		}
	}
	return nil
}

// Observe implements the registry's expected reload callback. It opens,
// closes, or replaces the underlying store based on db_path changes and
// rebuilds the tenant configuration map.
//
// Register this via Registry.AddReloadObserver(FeatureName, f.Observe)
// for globals and via a separate pipeline (driven by RegisterTenants)
// for per-tenant overrides. The feature keeps the last observed globals
// and tenants together so subsequent lookups resolve correctly.
func (f *Feature) Observe(snap shared.FeatureSnapshot) {
	enabled := snap.Enabled
	f.enabled.Store(enabled)

	newCfg := parseParams(snap.Params)

	f.mu.Lock()
	oldPath := f.globalCfg.DBPath
	oldStore := f.store
	f.globalCfg = newCfg
	f.mu.Unlock()

	// When the feature is disabled, release the file handle so
	// operators can delete the database without restarting. Re-enable
	// later will reopen.
	if !enabled {
		if oldStore != nil {
			f.mu.Lock()
			f.store = nil
			f.mu.Unlock()
			_ = oldStore.Close()
		}
		return
	}

	// Reopen the store if the path changed or none is live yet.
	if oldStore == nil || oldPath != newCfg.DBPath {
		saltFile := ""
		if newCfg.SaltedHashes {
			saltFile = newCfg.SaltFile
		}
		newStore, err := f.openStore(newCfg.DBPath, saltFile)
		if err != nil {
			// Leave the previous store (if any) running. The feature
			// becomes stale rather than crashing the gateway.
			return
		}
		f.mu.Lock()
		f.store = newStore
		f.mu.Unlock()
		if oldStore != nil {
			_ = oldStore.Close()
		}
	}
}

// RegisterTenants replaces the tenant-specific parameter overrides.
// Call this whenever a Reload fires with a new tenants map; only the
// ttl_blocklist feature snapshot from each tenant is extracted.
func (f *Feature) RegisterTenants(tenants map[string]feature.TenantSnapshot) {
	next := make(map[string]Params, len(tenants))
	for host, t := range tenants {
		snap, ok := t.Features[FeatureName]
		if !ok || !snap.Enabled {
			continue
		}
		next[host] = parseParams(snap.Params)
	}
	f.mu.Lock()
	f.tenantCfg = next
	f.mu.Unlock()
}

// effectiveParams returns the parameters that apply to a given tenant
// host. Tenant overrides win; otherwise globals.
func (f *Feature) effectiveParams(host string) (Params, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if p, ok := f.tenantCfg[host]; ok {
		return p, true
	}
	// Tenant absent => use globals only when feature is globally on.
	if f.enabled.Load() {
		return f.globalCfg, true
	}
	return Params{}, false
}

// Store returns the live store. Returns nil when the feature is
// disabled. Exposed so the admin/abuse-reporting layer can call Add
// without re-constructing the store.
func (f *Feature) Store() *Store {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.store
}

// SetStore swaps the live store. Primarily for tests; in production the
// store is owned by Observe.
func (f *Feature) SetStore(s *Store) {
	f.mu.Lock()
	old := f.store
	f.store = s
	f.mu.Unlock()
	if old != nil && old != s {
		_ = old.Close()
	}
}

// Start launches the background sweeper. Calling Start twice is a no-op
// — the existing sweeper is reused. The sweeper runs until Stop is
// called or the Feature is garbage-collected.
func (f *Feature) Start(ctx context.Context) {
	f.sweepMu.Lock()
	defer f.sweepMu.Unlock()
	if f.sweeperCancel != nil {
		return
	}
	sCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	f.sweeperCancel = cancel
	f.sweeperDone = done

	interval := f.sweepInterval
	if interval <= 0 {
		interval = defaultSweepInterval
	}

	go func() {
		defer close(done)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-sCtx.Done():
				return
			case <-t.C:
				if s := f.Store(); s != nil {
					_ = s.Sweep()
				}
			}
		}
	}()
}

// Stop terminates the sweeper goroutine and waits for it to exit.
func (f *Feature) Stop() {
	f.sweepMu.Lock()
	cancel := f.sweeperCancel
	done := f.sweeperDone
	f.sweeperCancel = nil
	f.sweeperDone = nil
	f.sweepMu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	if done != nil {
		<-done
	}
}

// SetSweepInterval overrides the default 10-minute sweep cadence. Must
// be called before Start; changes after Start are ignored.
func (f *Feature) SetSweepInterval(d time.Duration) {
	f.sweepMu.Lock()
	f.sweepInterval = d
	f.sweepMu.Unlock()
}

// Middleware satisfies feature.Feature. The returned wrapper checks
// the fast-path atomic first, resolves the effective tenant snapshot
// via the resolver, and applies the configured action when the
// request's IP is in the store.
func (f *Feature) Middleware(resolver feature.Resolver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !f.enabled.Load() {
				next.ServeHTTP(w, r)
				return
			}

			tenant := feature.TenantFromContext(r.Context())
			host := ""
			if tenant != nil {
				host = tenant.Host
			}

			params, ok := f.effectiveParams(host)
			if !ok {
				next.ServeHTTP(w, r)
				return
			}

			// Tenant-level snapshot can still be disabled; check it.
			if tenant != nil {
				if snap, exists := tenant.Features[FeatureName]; exists && !snap.Enabled {
					next.ServeHTTP(w, r)
					return
				}
			} else if resolver != nil {
				snap := resolver.Resolve(r, FeatureName)
				if !snap.Enabled {
					next.ServeHTTP(w, r)
					return
				}
			}

			s := f.Store()
			if s == nil {
				next.ServeHTTP(w, r)
				return
			}

			ip := resolveClientIP(r, params.TrustXFF)
			if ip == "" {
				next.ServeHTTP(w, r)
				return
			}

			if !s.Contains(host, ip) {
				next.ServeHTTP(w, r)
				return
			}

			applyAction(w, r, params.Action, params.DefaultTTL)
		})
	}
}

// applyAction writes the block response corresponding to action. The
// timeout mode intentionally sleeps up to ttl before returning, giving
// hostile clients no informative signal.
func applyAction(w http.ResponseWriter, r *http.Request, action shared.BlockAction, ttl time.Duration) {
	switch action {
	case shared.BlockActionNotFound:
		w.WriteHeader(http.StatusNotFound)
	case shared.BlockActionTooMany:
		w.Header().Set("Retry-After", fmt.Sprintf("%.0f", ttl.Seconds()))
		w.WriteHeader(http.StatusTooManyRequests)
	case shared.BlockActionTimeout:
		// Use the request context so shutdown unblocks us.
		timer := time.NewTimer(ttl)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-r.Context().Done():
		}
		// Either way, terminate the exchange silently.
		hijackAndClose(w)
	case shared.BlockActionDrop:
		fallthrough
	default:
		hijackAndClose(w)
	}
}

// hijackAndClose silently tears down the connection when possible. The
// fallback is a 400 with no body — it still signals "your request is
// over" without advertising anything useful.
func hijackAndClose(w http.ResponseWriter) {
	if hj, ok := w.(http.Hijacker); ok {
		conn, _, err := hj.Hijack()
		if err == nil {
			_ = conn.Close()
			return
		}
	}
	w.WriteHeader(http.StatusBadRequest)
}

// resolveClientIP figures out the IP to look up. When trustXFF is on,
// the leftmost X-Forwarded-For entry wins; otherwise only RemoteAddr.
// A bare IP is accepted directly; a host:port is split. Returns the
// empty string when no IP can be extracted.
func resolveClientIP(r *http.Request, trustXFF bool) string {
	if trustXFF {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.IndexByte(xff, ','); i > 0 {
				xff = xff[:i]
			}
			ip := strings.TrimSpace(xff)
			if ip != "" {
				return ip
			}
		}
	}
	if r.RemoteAddr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}
