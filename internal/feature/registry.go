package feature

import (
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"

	"gateway/internal/shared"
)

// Feature is the contract implemented by every registrable capability.
// Middleware is called once at registry-chain build time; Validate is
// called on every reload against every tenant's effective snapshot.
type Feature interface {
	// Name returns the stable identifier used in configuration maps. It
	// must be constant for the lifetime of the process and unique across
	// features registered on the same Registry.
	Name() string

	// Middleware returns an http.Handler wrapper. The returned wrapper is
	// installed into the pipeline exactly once; runtime enablement is
	// communicated via the Resolver (or observer callbacks) so that the
	// handler is constructed once and never rebuilt.
	Middleware(resolver Resolver) func(http.Handler) http.Handler

	// Validate inspects a candidate snapshot and returns an error if it
	// would not be safe to apply. It must be pure: no state mutation, no
	// side effects.
	Validate(cfg shared.FeatureSnapshot) error
}

// ReloadObserver is invoked once per registered callback each time the
// Registry successfully applies a new snapshot. The supplied snapshot is
// the feature's effective globals value; tenant-specific overrides are
// resolved per-request via a Resolver.
type ReloadObserver func(snapshot shared.FeatureSnapshot)

// snapshotState is the immutable configuration payload. A new value is
// allocated on every successful Reload and published atomically so that
// concurrent readers see a consistent globals+tenants view.
type snapshotState struct {
	globals GlobalsSnapshot
	tenants map[string]TenantSnapshot
}

// Registry holds registered features and the current runtime snapshot.
// Registration is expected at process startup; BuildChain and Reload may
// then run concurrently with request handling.
type Registry struct {
	mu        sync.RWMutex
	order     []string
	features  map[string]Feature
	observers map[string][]ReloadObserver

	current atomic.Pointer[snapshotState]
}

// NewRegistry constructs an empty Registry with a zero-value snapshot.
func NewRegistry() *Registry {
	r := &Registry{
		features:  make(map[string]Feature),
		observers: make(map[string][]ReloadObserver),
	}
	r.current.Store(&snapshotState{
		globals: GlobalsSnapshot{Features: map[string]shared.FeatureSnapshot{}},
		tenants: map[string]TenantSnapshot{},
	})
	return r
}

// Register adds a feature to the registry. It panics if a feature with
// the same Name is already registered; duplicate registration is always
// a programming error and there is no safe way to continue.
func (r *Registry) Register(f Feature) {
	if f == nil {
		panic("feature: Register called with nil Feature")
	}
	name := f.Name()
	if name == "" {
		panic("feature: Feature.Name returned empty string")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.features[name]; exists {
		panic(fmt.Sprintf("feature: duplicate registration for %q", name))
	}
	r.features[name] = f
	r.order = append(r.order, name)
}

// AddReloadObserver registers a callback fired on every successful Reload
// with the effective globals snapshot for the named feature. It is the
// primary mechanism by which features cache an atomic enabled flag so
// that middleware can branch without map lookups per request.
func (r *Registry) AddReloadObserver(featureName string, obs ReloadObserver) {
	if obs == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.observers[featureName] = append(r.observers[featureName], obs)
}

// Names returns the registered feature names in registration order. The
// returned slice is a copy; callers may mutate it freely.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, len(r.order))
	copy(out, r.order)
	return out
}

// BuildChain composes every registered feature's middleware around inner,
// preserving registration order. The outermost handler corresponds to the
// first-registered feature; the innermost is the last-registered feature
// wrapping inner directly. Features are responsible for observing their
// enabled state via the Resolver or a ReloadObserver and short-circuiting
// cheaply when disabled.
func (r *Registry) BuildChain(inner http.Handler) http.Handler {
	r.mu.RLock()
	defer r.mu.RUnlock()

	resolver := &registryResolver{reg: r}

	h := inner
	// Compose in reverse so that order[0] ends up outermost.
	for i := len(r.order) - 1; i >= 0; i-- {
		f := r.features[r.order[i]]
		mw := f.Middleware(resolver)
		if mw == nil {
			continue
		}
		h = mw(h)
	}
	return h
}

// Reload validates the candidate configuration against every registered
// feature for the globals snapshot and for every tenant's effective
// snapshot. If any Validate returns an error, all errors are collected
// via errors.Join and the registry's current snapshot is left unchanged.
// On success the new snapshot is published atomically and every reload
// observer is invoked with its feature's effective globals value.
func (r *Registry) Reload(globals GlobalsSnapshot, tenants map[string]TenantSnapshot) error {
	r.mu.RLock()
	order := make([]string, len(r.order))
	copy(order, r.order)
	features := make(map[string]Feature, len(r.features))
	for k, v := range r.features {
		features[k] = v
	}
	observers := make(map[string][]ReloadObserver, len(r.observers))
	for k, v := range r.observers {
		cp := make([]ReloadObserver, len(v))
		copy(cp, v)
		observers[k] = cp
	}
	r.mu.RUnlock()

	if globals.Features == nil {
		globals.Features = map[string]shared.FeatureSnapshot{}
	}
	if tenants == nil {
		tenants = map[string]TenantSnapshot{}
	}

	// Two-phase: validate everything first, then swap atomically on success.
	var errs []error
	for _, name := range order {
		f := features[name]
		gCfg := globals.Features[name]
		if err := f.Validate(gCfg); err != nil {
			errs = append(errs, fmt.Errorf("feature %q globals: %w", name, err))
		}
		for host, tenant := range tenants {
			cfg := gCfg
			if override, ok := tenant.Features[name]; ok {
				cfg = override
			}
			if err := f.Validate(cfg); err != nil {
				errs = append(errs, fmt.Errorf("feature %q tenant %q: %w", name, host, err))
			}
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	// Copy maps defensively so that callers mutating their inputs after
	// Reload returns do not race with resolve calls.
	gCopy := GlobalsSnapshot{Features: make(map[string]shared.FeatureSnapshot, len(globals.Features))}
	for k, v := range globals.Features {
		gCopy.Features[k] = v
	}
	tCopy := make(map[string]TenantSnapshot, len(tenants))
	for host, tenant := range tenants {
		ft := make(map[string]shared.FeatureSnapshot, len(tenant.Features))
		for k, v := range tenant.Features {
			ft[k] = v
		}
		tCopy[host] = TenantSnapshot{
			Host:     tenant.Host,
			Enabled:  tenant.Enabled,
			Features: ft,
		}
	}

	r.current.Store(&snapshotState{globals: gCopy, tenants: tCopy})

	for _, name := range order {
		cfg := gCopy.Features[name]
		for _, obs := range observers[name] {
			obs(cfg)
		}
	}

	return nil
}

// snapshot returns the currently published snapshot pointer. Callers must
// not mutate the returned value.
func (r *Registry) snapshot() *snapshotState {
	return r.current.Load()
}

// Tenants returns the current published tenant map. The returned map is
// the canonical stored copy; callers must not mutate it.
func (r *Registry) Tenants() map[string]TenantSnapshot {
	s := r.snapshot()
	if s == nil {
		return nil
	}
	return s.tenants
}

// Globals returns the current published globals snapshot. The returned
// map inside must not be mutated by callers.
func (r *Registry) Globals() GlobalsSnapshot {
	s := r.snapshot()
	if s == nil {
		return GlobalsSnapshot{Features: map[string]shared.FeatureSnapshot{}}
	}
	return s.globals
}
