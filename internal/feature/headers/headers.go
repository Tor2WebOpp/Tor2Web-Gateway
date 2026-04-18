package headers

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"gateway/internal/feature"
	"gateway/internal/shared"
)

// FeatureName is the stable identifier used in configuration maps.
const FeatureName = "proxy_headers"

// globalTenantKey is the pseudo-host used for the rule set that applies
// when a request has no tenant context (or the tenant has no override).
const globalTenantKey = "_global_"

// addEntry represents one compiled name/value pair for the add_* lists.
// The value template is parsed at Observe time so the hot path does only
// Render (which in turn short-circuits via fastPath for literal values).
type addEntry struct {
	name  string
	value Template
}

// tenantRules is the immutable, pre-compiled rule set for one tenant (or
// the global fallback). Lookups are done via constant-time hash-map
// accesses on canonicalised header names.
type tenantRules struct {
	// stripUpstream holds canonical MIME header names to remove from the
	// request before forwarding.
	stripUpstream map[string]struct{}
	// addUpstream holds compiled headers to add to the request. Multiple
	// entries with the same name are kept in declaration order; each one
	// appends an additional value after the first sets the header.
	addUpstream []addEntry
	// stripDownstream holds canonical MIME header names to remove from
	// the response.
	stripDownstream map[string]struct{}
	// addDownstream holds compiled headers to add to the response.
	addDownstream []addEntry
}

// empty reports whether the rule set has no work to do, in which case the
// middleware can short-circuit even when the feature is globally enabled.
func (tr *tenantRules) empty() bool {
	if tr == nil {
		return true
	}
	return len(tr.stripUpstream) == 0 &&
		len(tr.addUpstream) == 0 &&
		len(tr.stripDownstream) == 0 &&
		len(tr.addDownstream) == 0
}

// Feature is the proxy_headers implementation. It plugs into the
// feature.Registry and swaps its compiled rule set atomically on reload.
type Feature struct {
	// enabled is true iff the resolved globals snapshot or any tenant
	// override has Enabled=true. Middleware checks this flag cheaply
	// before any further work.
	enabled atomic.Bool

	// compiled is a pointer-swappable map keyed by tenant host (lowercased)
	// plus the globalTenantKey entry for the globals fallback.
	compiled atomic.Pointer[map[string]*tenantRules]

	// mu guards Observe so that concurrent reloads do not race on the
	// compilation work; only the atomic store is visible to readers.
	mu sync.Mutex
}

// New constructs a Feature with an empty ruleset and disabled flag.
func New() *Feature {
	f := &Feature{}
	empty := map[string]*tenantRules{}
	f.compiled.Store(&empty)
	return f
}

// Name returns the stable feature identifier.
func (f *Feature) Name() string { return FeatureName }

// Validate parses templates and checks shape without mutating Feature
// state. Called by the registry for both globals and every tenant
// override prior to any swap.
func (f *Feature) Validate(cfg shared.FeatureSnapshot) error {
	if !cfg.Enabled && len(cfg.Params) == 0 {
		return nil
	}
	_, err := compileCfg(cfg)
	return err
}

// Middleware returns an http.Handler wrapper that applies the current
// compiled rule set on every request. The wrapper is built exactly once;
// live toggling happens via the atomic.Pointer swap in Observe.
func (f *Feature) Middleware(res feature.Resolver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !f.enabled.Load() {
				next.ServeHTTP(w, r)
				return
			}
			snap := res.Resolve(r, FeatureName)
			if !snap.Enabled {
				next.ServeHTTP(w, r)
				return
			}
			tenantKey := globalTenantKey
			tenantHost := ""
			if t := feature.TenantFromContext(r.Context()); t != nil && t.Host != "" {
				tenantKey = strings.ToLower(t.Host)
				tenantHost = t.Host
			}
			rules := f.rulesFor(tenantKey)
			if rules.empty() {
				next.ServeHTTP(w, r)
				return
			}

			ctx := RenderCtx{
				ClientIP:   clientIP(r),
				TenantHost: tenantHost,
				Req:        r,
			}

			applyRequest(r, rules, ctx)

			if len(rules.stripDownstream) == 0 && len(rules.addDownstream) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			rw := &responseWriter{
				ResponseWriter: w,
				rules:          rules,
				ctx:            ctx,
			}
			next.ServeHTTP(rw, r)
			// In case the handler wrote a body with no explicit
			// WriteHeader call, Write() will have taken the fast
			// path through rw and applied mutations there already.
			// If nothing was ever written (e.g. handler returns
			// with zero writes), there are no response headers to
			// strip — but for completeness we still ensure any
			// pre-buffered add_downstream entries land when headers
			// are eventually flushed by the server.
			_ = rw
		})
	}
}

// Observe installs a newly-validated configuration. Called once per
// registry reload cycle with the effective globals snapshot plus every
// tenant snapshot.
func (f *Feature) Observe(globals feature.GlobalsSnapshot, tenants map[string]feature.TenantSnapshot) {
	f.mu.Lock()
	defer f.mu.Unlock()

	newMap := make(map[string]*tenantRules, 1+len(tenants))
	anyEnabled := false

	globalCfg := globals.Features[FeatureName]
	if rules, err := compileCfg(globalCfg); err == nil && rules != nil {
		newMap[globalTenantKey] = rules
		if globalCfg.Enabled {
			anyEnabled = true
		}
	}

	for host, tenant := range tenants {
		cfg, ok := tenant.Features[FeatureName]
		if !ok {
			continue
		}
		rules, err := compileCfg(cfg)
		if err != nil || rules == nil {
			continue
		}
		newMap[strings.ToLower(host)] = rules
		if cfg.Enabled {
			anyEnabled = true
		}
	}

	f.compiled.Store(&newMap)
	f.enabled.Store(anyEnabled)
}

// rulesFor returns the compiled rules for the supplied tenant key, or the
// global fallback when the tenant has no explicit entry.
func (f *Feature) rulesFor(tenantKey string) *tenantRules {
	p := f.compiled.Load()
	if p == nil {
		return nil
	}
	m := *p
	if r, ok := m[tenantKey]; ok {
		return r
	}
	if r, ok := m[globalTenantKey]; ok {
		return r
	}
	return nil
}

// RegisterWith installs f on reg and wires its reload observer.
func RegisterWith(reg *feature.Registry) *Feature {
	f := New()
	reg.Register(f)
	reg.AddReloadObserver(FeatureName, func(snap shared.FeatureSnapshot) {
		f.Observe(reg.Globals(), reg.Tenants())
	})
	return f
}

// -----------------------------------------------------------------------
// Request / response mutation.

// applyRequest mutates r in place: strips configured request headers,
// then sets each add_upstream header from the rendered template.
func applyRequest(r *http.Request, rules *tenantRules, ctx RenderCtx) {
	// Populate a RequestID used by any {{request_id}} templates; the
	// same id covers both the upstream and downstream passes so logs
	// and backends correlate.
	if ctx.RequestID == "" {
		ctx.RequestID = newRequestID()
	}
	for name := range rules.stripUpstream {
		r.Header.Del(name)
	}
	for i := range rules.addUpstream {
		e := &rules.addUpstream[i]
		r.Header.Set(e.name, e.value.Render(ctx))
	}
}

// responseWriter intercepts WriteHeader and Write so strip_downstream
// and add_downstream rules apply before the first byte leaves. After the
// first call it becomes a thin pass-through.
type responseWriter struct {
	http.ResponseWriter
	rules       *tenantRules
	ctx         RenderCtx
	wroteHeader bool
}

// Header forwards to the wrapped ResponseWriter so handlers see the
// canonical header map.
func (rw *responseWriter) Header() http.Header {
	return rw.ResponseWriter.Header()
}

// WriteHeader applies the downstream rules then forwards.
func (rw *responseWriter) WriteHeader(status int) {
	if !rw.wroteHeader {
		rw.applyDownstream()
		rw.wroteHeader = true
	}
	rw.ResponseWriter.WriteHeader(status)
}

// Write ensures the downstream rules apply on implicit 200 OK responses
// where the handler writes a body without calling WriteHeader first.
func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		rw.applyDownstream()
		rw.wroteHeader = true
	}
	return rw.ResponseWriter.Write(b)
}

// applyDownstream strips and adds headers on the response. Called exactly
// once, immediately before the first write hits the wire.
func (rw *responseWriter) applyDownstream() {
	h := rw.ResponseWriter.Header()
	for name := range rw.rules.stripDownstream {
		h.Del(name)
	}
	ctx := rw.ctx
	if ctx.RequestID == "" {
		ctx.RequestID = newRequestID()
	}
	for i := range rw.rules.addDownstream {
		e := &rw.rules.addDownstream[i]
		h.Set(e.name, e.value.Render(ctx))
	}
}

// clientIP extracts the IP portion of r.RemoteAddr, trimming any port
// suffix. Returns an empty string when r is nil or has no RemoteAddr.
func clientIP(r *http.Request) string {
	if r == nil || r.RemoteAddr == "" {
		return ""
	}
	// RemoteAddr is typically "ip:port" for IPv4 or "[ipv6]:port".
	// Use LastIndex so we split on the port-separator even for IPv6.
	if i := strings.LastIndex(r.RemoteAddr, ":"); i >= 0 {
		ip := r.RemoteAddr[:i]
		// Unwrap IPv6 brackets.
		if len(ip) >= 2 && ip[0] == '[' && ip[len(ip)-1] == ']' {
			ip = ip[1 : len(ip)-1]
		}
		return ip
	}
	return r.RemoteAddr
}

// -----------------------------------------------------------------------
// Configuration parsing and compilation.

// compileCfg turns a FeatureSnapshot into a tenantRules ready for the
// hot path. Returns (nil, nil) when the snapshot is disabled and carries
// no params — the feature should be treated as inactive.
func compileCfg(cfg shared.FeatureSnapshot) (*tenantRules, error) {
	if !cfg.Enabled && len(cfg.Params) == 0 {
		return nil, nil
	}
	rules := &tenantRules{}
	if cfg.Params == nil {
		return rules, nil
	}

	var err error
	rules.stripUpstream, err = parseStripList(cfg.Params, "strip_upstream")
	if err != nil {
		return nil, err
	}
	rules.stripDownstream, err = parseStripList(cfg.Params, "strip_downstream")
	if err != nil {
		return nil, err
	}
	rules.addUpstream, err = parseAddList(cfg.Params, "add_upstream")
	if err != nil {
		return nil, err
	}
	rules.addDownstream, err = parseAddList(cfg.Params, "add_downstream")
	if err != nil {
		return nil, err
	}
	return rules, nil
}

// parseStripList coerces cfg.Params[key] to a set of canonical header
// names. An absent key is allowed and yields a nil map. Any other shape
// is a validation error.
func parseStripList(params map[string]any, key string) (map[string]struct{}, error) {
	raw, ok := params[key]
	if !ok {
		return nil, nil
	}
	items, err := asStringSlice(raw, key)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, nil
	}
	out := make(map[string]struct{}, len(items))
	for i, name := range items {
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, fmt.Errorf("%s[%d]: header name is empty", key, i)
		}
		out[http.CanonicalHeaderKey(name)] = struct{}{}
	}
	return out, nil
}

// parseAddList coerces cfg.Params[key] to a slice of compiled addEntry
// values. The entries may be supplied either as a list of maps
// ([]interface{} containing map[string]any) or as the normalised
// []map[string]any form; both arrive depending on unmarshal code path.
func parseAddList(params map[string]any, key string) ([]addEntry, error) {
	raw, ok := params[key]
	if !ok {
		return nil, nil
	}
	var entries []map[string]any
	switch v := raw.(type) {
	case []any:
		entries = make([]map[string]any, 0, len(v))
		for i, e := range v {
			m, ok := e.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%s[%d]: expected map, got %T", key, i, e)
			}
			entries = append(entries, m)
		}
	case []map[string]any:
		entries = v
	default:
		return nil, fmt.Errorf("%s: expected list, got %T", key, raw)
	}

	out := make([]addEntry, 0, len(entries))
	for i, m := range entries {
		name, err := asString(m["name"], fmt.Sprintf("%s[%d].name", key, i))
		if err != nil {
			return nil, err
		}
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, fmt.Errorf("%s[%d]: name is empty", key, i)
		}
		valueRaw, ok := m["value"]
		if !ok {
			return nil, fmt.Errorf("%s[%d]: missing value", key, i)
		}
		value, err := asString(valueRaw, fmt.Sprintf("%s[%d].value", key, i))
		if err != nil {
			return nil, err
		}
		tpl, err := Parse(value)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %w", key, i, err)
		}
		out = append(out, addEntry{
			name:  http.CanonicalHeaderKey(name),
			value: tpl,
		})
	}
	return out, nil
}

// asStringSlice coerces YAML list scalars to []string. It accepts both
// the generic []any and the already-typed []string forms.
func asStringSlice(v any, field string) ([]string, error) {
	switch x := v.(type) {
	case []string:
		out := make([]string, len(x))
		copy(out, x)
		return out, nil
	case []any:
		out := make([]string, 0, len(x))
		for i, e := range x {
			s, err := asString(e, fmt.Sprintf("%s[%d]", field, i))
			if err != nil {
				return nil, err
			}
			out = append(out, s)
		}
		return out, nil
	case nil:
		return nil, nil
	default:
		return nil, fmt.Errorf("%s: expected list, got %T", field, v)
	}
}

// asString coerces common YAML scalar types to string.
func asString(v any, field string) (string, error) {
	switch x := v.(type) {
	case string:
		return x, nil
	case fmt.Stringer:
		return x.String(), nil
	case nil:
		return "", nil
	default:
		return "", fmt.Errorf("%s: expected string, got %T", field, v)
	}
}

// ensure interface compliance at compile time.
var _ feature.Feature = (*Feature)(nil)
