package feature

import (
	"net/http"

	"gateway/internal/shared"
)

// GlobalsSnapshot is the immutable feature configuration that applies to
// every tenant unless explicitly overridden.
type GlobalsSnapshot struct {
	Features map[string]shared.FeatureSnapshot
}

// TenantSnapshot is the immutable configuration of a single tenant. Host is
// the lowercased public hostname used for routing. Features may override
// any subset of the global feature map; unmentioned features fall back to
// globals.
type TenantSnapshot struct {
	Host     string
	Enabled  bool
	Features map[string]shared.FeatureSnapshot
}

// Resolver returns the effective FeatureSnapshot for a given request and
// feature name. Implementations must be safe for concurrent use.
type Resolver interface {
	Resolve(r *http.Request, featureName string) shared.FeatureSnapshot
}

// registryResolver is the default Resolver implementation. It reads the
// current snapshot directly from the associated Registry so that reloads
// are observed without any additional plumbing.
type registryResolver struct {
	reg *Registry
}

// Resolve applies the precedence: tenant override, then globals, then a
// zero snapshot representing a disabled feature.
func (rr *registryResolver) Resolve(r *http.Request, featureName string) shared.FeatureSnapshot {
	snap := rr.reg.snapshot()
	if r != nil {
		if tenant := TenantFromContext(r.Context()); tenant != nil {
			if fs, ok := tenant.Features[featureName]; ok {
				return fs
			}
		}
	}
	if snap != nil && snap.globals.Features != nil {
		if fs, ok := snap.globals.Features[featureName]; ok {
			return fs
		}
	}
	return shared.FeatureSnapshot{}
}
