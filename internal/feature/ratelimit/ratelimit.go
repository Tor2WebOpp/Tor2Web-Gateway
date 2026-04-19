package ratelimit

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gateway/internal/feature"
	"gateway/internal/shared"

	"golang.org/x/time/rate"
)

// FeatureName is the registry identifier under which this feature publishes
// its configuration and is resolved at request time.
const FeatureName = "rate_limit"

// Default parameter values. Chosen to match the existing single-tenant
// implementation in internal/proxy/ratelimit.go so behaviour is preserved
// when this feature replaces it in wave 3.
const (
	defaultPerIPRPS        = 10.0
	defaultPerIPBurst      = 20
	defaultPerIPConns      = 50
	defaultAPIRPS          = 5.0
	defaultAPIBurst        = 10
	defaultGlobalRPS       = 1000.0
	defaultCleanupSeconds  = 300
	defaultIdleTTLSeconds  = 600 // visitors unseen for this long are swept.
	defaultTimeoutSeconds  = 30
	defaultActionOnExceed  = "429"
	defaultAPIPathPrefix   = "/api/"
)

// Action indicates what to do when a limit is exceeded.
type Action string

const (
	ActionTooMany Action = "429"
	ActionDrop    Action = "drop"
	ActionTimeout Action = "timeout"
)

func (a Action) normalized() Action {
	switch a {
	case ActionTooMany, ActionDrop, ActionTimeout:
		return a
	}
	return ActionTooMany
}

// params is the decoded, validated shape of a FeatureSnapshot.Params map.
type params struct {
	PerIPRPS         float64
	PerIPBurst       int
	PerIPConns       int
	APIRPS           float64
	APIBurst         int
	APIPathPrefixes  []string
	GlobalRPS        float64
	CleanupInterval  time.Duration
	IdleTTL          time.Duration
	TrustXFF         bool
	ActionOnExceed   Action
	TimeoutOnExceed  time.Duration
}

// defaultParams returns the baseline values used when a key is absent or
// type-mismatched. New per-tenant states inherit this baseline then layer
// tenant-specific overrides on top.
func defaultParams() params {
	return params{
		PerIPRPS:        defaultPerIPRPS,
		PerIPBurst:      defaultPerIPBurst,
		PerIPConns:      defaultPerIPConns,
		APIRPS:          defaultAPIRPS,
		APIBurst:        defaultAPIBurst,
		APIPathPrefixes: []string{defaultAPIPathPrefix},
		GlobalRPS:       defaultGlobalRPS,
		CleanupInterval: time.Duration(defaultCleanupSeconds) * time.Second,
		IdleTTL:         time.Duration(defaultIdleTTLSeconds) * time.Second,
		TrustXFF:        false,
		ActionOnExceed:  ActionTooMany,
		TimeoutOnExceed: time.Duration(defaultTimeoutSeconds) * time.Second,
	}
}

// parseParams decodes a FeatureSnapshot.Params map into a params struct,
// layering over the defaults. Absent or wrongly-typed entries fall back to
// defaults; this deliberately mirrors the philosophy of the rest of the
// feature tree where a reload never aborts because a single tunable is
// formatted oddly.
func parseParams(p map[string]any) params {
	out := defaultParams()
	if p == nil {
		return out
	}

	if v, ok := asFloat(p["per_ip_rps"]); ok {
		out.PerIPRPS = v
	}
	if v, ok := asInt(p["per_ip_burst"]); ok {
		out.PerIPBurst = v
	}
	if v, ok := asInt(p["per_ip_conns"]); ok {
		out.PerIPConns = v
	}
	if v, ok := asFloat(p["api_rps"]); ok {
		out.APIRPS = v
	}
	if v, ok := asInt(p["api_burst"]); ok {
		out.APIBurst = v
	}
	if v, ok := asFloat(p["global_rps"]); ok {
		out.GlobalRPS = v
	}
	if v, ok := asInt(p["cleanup_interval_seconds"]); ok && v > 0 {
		out.CleanupInterval = time.Duration(v) * time.Second
		// Keep idle TTL proportional — a visitor survives ~2 cleanup cycles.
		out.IdleTTL = 2 * out.CleanupInterval
	}
	if v, ok := asInt(p["idle_ttl_seconds"]); ok && v > 0 {
		out.IdleTTL = time.Duration(v) * time.Second
	}
	if v, ok := asBool(p["trust_xff"]); ok {
		out.TrustXFF = v
	}
	if prefixes, ok := asStringSlice(p["api_path_prefixes"]); ok {
		out.APIPathPrefixes = prefixes
	}
	if v, ok := p["action_on_exceed"].(string); ok {
		out.ActionOnExceed = Action(v).normalized()
	}
	if v, ok := asInt(p["timeout_on_exceed_seconds"]); ok && v > 0 {
		out.TimeoutOnExceed = time.Duration(v) * time.Second
	}
	return out
}

// asFloat coerces common numeric types into float64. YAML decoders may
// return int, int64, float64, or json.Number-like strings; supporting the
// common few keeps configuration ergonomic.
func asFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case int32:
		return float64(x), true
	case uint:
		return float64(x), true
	case uint64:
		return float64(x), true
	}
	return 0, false
}

// asInt coerces common integer-ish types to int. Float values are accepted
// and truncated — useful when YAML round-trips an integer as float64.
func asInt(v any) (int, bool) {
	switch x := v.(type) {
	case int:
		return x, true
	case int64:
		return int(x), true
	case int32:
		return int(x), true
	case uint:
		return int(x), true
	case uint64:
		return int(x), true
	case float64:
		return int(x), true
	case float32:
		return int(x), true
	}
	return 0, false
}

func asBool(v any) (bool, bool) {
	if b, ok := v.(bool); ok {
		return b, true
	}
	return false, false
}

// asStringSlice accepts either []string or []any (YAML parsers often return
// the latter) and returns a fresh []string.
func asStringSlice(v any) ([]string, bool) {
	switch s := v.(type) {
	case []string:
		out := make([]string, len(s))
		copy(out, s)
		return out, true
	case []any:
		out := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				out = append(out, str)
			}
		}
		return out, true
	}
	return nil, false
}

// visitor is a single-IP record of a rate limiter and the last time it was
// touched; the cleanup goroutine uses lastSeen to evict idle records.
type visitor struct {
	limiter  *rate.Limiter
	lastSeen atomic.Int64 // UnixNano of last Allow() attempt
}

func newVisitor(lim *rate.Limiter, now time.Time) *visitor {
	v := &visitor{limiter: lim}
	v.lastSeen.Store(now.UnixNano())
	return v
}

// limiterCache is a thin sync.Map wrapper that creates per-IP limiters on
// demand. It mirrors the shape of proxy/ratelimit.go's visitor map so the
// cost model carries over.
type limiterCache struct {
	m       sync.Map // ip -> *visitor
	makeLim func() *rate.Limiter
}

func newLimiterCache(make func() *rate.Limiter) *limiterCache {
	return &limiterCache{makeLim: make}
}

// getOrCreate returns (creating if necessary) the limiter for ip and stamps
// its lastSeen to now.
func (c *limiterCache) getOrCreate(ip string, now time.Time) *rate.Limiter {
	if val, ok := c.m.Load(ip); ok {
		v := val.(*visitor)
		v.lastSeen.Store(now.UnixNano())
		return v.limiter
	}
	v := newVisitor(c.makeLim(), now)
	actual, loaded := c.m.LoadOrStore(ip, v)
	if loaded {
		existing := actual.(*visitor)
		existing.lastSeen.Store(now.UnixNano())
		return existing.limiter
	}
	return v.limiter
}

// sweep removes visitors whose lastSeen is older than cutoff. It returns
// the number of entries removed — primarily for test observability.
func (c *limiterCache) sweep(cutoff time.Time) int {
	cutoffNano := cutoff.UnixNano()
	removed := 0
	c.m.Range(func(k, v any) bool {
		vis := v.(*visitor)
		if vis.lastSeen.Load() < cutoffNano {
			c.m.Delete(k)
			removed++
		}
		return true
	})
	return removed
}

// size reports the number of entries currently held. Test-only.
func (c *limiterCache) size() int {
	n := 0
	c.m.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

// connTracker counts concurrent connections for a single IP and records
// the UnixNano of the last touch so the sweeper can evict entries whose
// count has returned to zero and stayed that way past a cleanup
// interval. Keeps both fields atomic so the hot path remains lock-free.
type connTracker struct {
	count    atomic.Int64
	lastSeen atomic.Int64
}

// tenantState holds the per-tenant limiter fleet. It is immutable after
// construction (limiter pointers are stable for the tenantState's lifetime
// even though the per-limiter token state mutates under rate.Limiter's
// lock). Reloads replace the whole tenantState pointer atomically.
type tenantState struct {
	cfg           params
	ipBuckets     *limiterCache
	apiBuckets    *limiterCache
	connCounts    sync.Map // ip -> *connTracker
	globalLimiter *rate.Limiter
	apiLimiter    *rate.Limiter
}

func newTenantState(p params) *tenantState {
	cfg := p
	return &tenantState{
		cfg: cfg,
		ipBuckets: newLimiterCache(func() *rate.Limiter {
			return rate.NewLimiter(rate.Limit(cfg.PerIPRPS), cfg.PerIPBurst)
		}),
		apiBuckets: newLimiterCache(func() *rate.Limiter {
			return rate.NewLimiter(rate.Limit(cfg.APIRPS), cfg.APIBurst)
		}),
		globalLimiter: newGlobalLimiter(cfg),
		apiLimiter:    nil, // currently unused; kept for future server-side API-wide cap.
	}
}

// newGlobalLimiter creates the global rate.Limiter; burst is never smaller
// than the per-IP burst (matches the old behaviour).
func newGlobalLimiter(p params) *rate.Limiter {
	burst := int(p.GlobalRPS)
	if burst < p.PerIPBurst {
		burst = p.PerIPBurst
	}
	if burst < 1 {
		burst = 1
	}
	return rate.NewLimiter(rate.Limit(p.GlobalRPS), burst)
}

// Feature is the registerable capability implementing per-tenant rate
// limiting. Lifetime: NewFeature -> Register on a feature.Registry ->
// Reload pumps config in. Stop() ends the background sweeper.
type Feature struct {
	enabled atomic.Bool

	mu            sync.RWMutex
	tenantBuckets map[string]*tenantState
	globalDefault params // default used when a tenant has no override

	// sweep coordination
	sweeperOnce sync.Once
	stopOnce    sync.Once
	sweeperDone chan struct{}
	sweeperWG   sync.WaitGroup
	// sweepInterval is set when the sweeper is started; tests may
	// shrink it by supplying cleanup_interval_seconds in params.
	sweepInterval atomic.Int64 // nanoseconds

	// testHook fires at the end of each sweep pass; nil in production.
	testHook func()
}

// NewFeature constructs an unenabled Feature with no tenants. Register it on
// a feature.Registry and then drive it with Reload (typically wired to the
// registry's reload observer).
func NewFeature() *Feature {
	f := &Feature{
		tenantBuckets: map[string]*tenantState{},
		globalDefault: defaultParams(),
		sweeperDone:   make(chan struct{}),
	}
	f.sweepInterval.Store(int64(defaultCleanupSeconds) * int64(time.Second))
	return f
}

// Name returns the registry identifier.
func (f *Feature) Name() string { return FeatureName }

// Validate inspects a candidate FeatureSnapshot. It rejects values that
// would produce a non-functional limiter (e.g. negative burst). It never
// mutates state.
//
// Validate inspects the raw Params rather than the parsed result so that
// defaulting in parseParams does not mask user-supplied bad values.
func (f *Feature) Validate(cfg shared.FeatureSnapshot) error {
	if cfg.Params == nil {
		return nil
	}
	p := cfg.Params
	if v, ok := asFloat(p["per_ip_rps"]); ok && v < 0 {
		return errors.New("per_ip_rps must be >= 0")
	}
	if v, ok := asInt(p["per_ip_burst"]); ok && v < 0 {
		return errors.New("per_ip_burst must be >= 0")
	}
	if v, ok := asInt(p["per_ip_conns"]); ok && v < 0 {
		return errors.New("per_ip_conns must be >= 0")
	}
	if v, ok := asFloat(p["api_rps"]); ok && v < 0 {
		return errors.New("api_rps must be >= 0")
	}
	if v, ok := asInt(p["api_burst"]); ok && v < 0 {
		return errors.New("api_burst must be >= 0")
	}
	if v, ok := asFloat(p["global_rps"]); ok && v < 0 {
		return errors.New("global_rps must be >= 0")
	}
	if v, ok := asInt(p["cleanup_interval_seconds"]); ok && v < 0 {
		return errors.New("cleanup_interval_seconds must be >= 0")
	}
	if v, ok := p["action_on_exceed"].(string); ok && v != "" {
		switch Action(v) {
		case ActionTooMany, ActionDrop, ActionTimeout:
		default:
			return errors.New(`action_on_exceed must be one of "429", "drop", "timeout"`)
		}
	}
	return nil
}

// Observe is the ReloadObserver counterpart: it rebuilds the global default
// params whenever the registry publishes a new globals snapshot for this
// feature. It must be registered with feature.Registry.AddReloadObserver.
func (f *Feature) Observe(snap shared.FeatureSnapshot) {
	f.mu.Lock()
	f.globalDefault = parseParams(snap.Params)
	f.enabled.Store(snap.Enabled)
	f.mu.Unlock()
	// Replace existing tenant states that used the old globals-only config.
	// Tenants with explicit overrides carry on; tenants that relied on
	// globals get refreshed lazily through ApplyTenants.
	f.sweepIntervalFromGlobals()
}

// sweepIntervalFromGlobals derives the shared sweeper tick from the global
// default. It is cheap to call; the sweeper picks up the new value on the
// next iteration.
func (f *Feature) sweepIntervalFromGlobals() {
	f.mu.RLock()
	iv := f.globalDefault.CleanupInterval
	f.mu.RUnlock()
	if iv <= 0 {
		iv = time.Duration(defaultCleanupSeconds) * time.Second
	}
	f.sweepInterval.Store(int64(iv))
}

// ApplyTenants rebuilds the per-tenant state map from the supplied snapshot
// list. Disabled tenants (Enabled == false) are omitted — their middleware
// invocation becomes a skip.
//
// The supplied tenantParams map is (tenant host) -> (effective params for
// this feature on that tenant). Callers typically produce it by resolving
// each tenant against the globals/override stack and parsing its Params.
func (f *Feature) ApplyTenants(tenantParams map[string]params) {
	newStates := make(map[string]*tenantState, len(tenantParams))
	for host, p := range tenantParams {
		newStates[host] = newTenantState(p)
	}
	f.mu.Lock()
	f.tenantBuckets = newStates
	f.mu.Unlock()
}

// ApplyFromSnapshots is a convenience that composes ApplyTenants from
// tenant snapshots. A tenant without a rate_limit override inherits the
// current globals.
func (f *Feature) ApplyFromSnapshots(tenants map[string]feature.TenantSnapshot) {
	f.mu.RLock()
	gdef := f.globalDefault
	f.mu.RUnlock()

	effective := make(map[string]params, len(tenants))
	for host, t := range tenants {
		if !t.Enabled {
			continue
		}
		if override, ok := t.Features[FeatureName]; ok {
			// If explicitly disabled for the tenant, skip.
			if !override.Enabled {
				continue
			}
			effective[host] = parseParams(override.Params)
			continue
		}
		effective[host] = gdef
	}
	f.ApplyTenants(effective)
}

// Start spawns the shared cleanup goroutine. Safe to call multiple times;
// only the first call has effect. Stop unwinds it.
func (f *Feature) Start() {
	f.sweeperOnce.Do(func() {
		f.sweeperWG.Add(1)
		go f.sweepLoop()
	})
}

// Stop ends the sweeper and waits for it to exit. Idempotent: concurrent
// and repeat calls are safe. Without stopOnce the previous check-then-close
// pattern was a landmine — two goroutines could both see the channel open,
// both call close, and panic. Single-caller today but trivial to make robust.
func (f *Feature) Stop() {
	f.stopOnce.Do(func() {
		close(f.sweeperDone)
	})
	f.sweeperWG.Wait()
}

// sweepLoop runs on a dynamic ticker. It re-reads sweepInterval at each
// iteration so reload-driven changes take effect without restart.
func (f *Feature) sweepLoop() {
	defer f.sweeperWG.Done()
	for {
		interval := time.Duration(f.sweepInterval.Load())
		if interval <= 0 {
			interval = time.Duration(defaultCleanupSeconds) * time.Second
		}
		t := time.NewTimer(interval)
		select {
		case <-f.sweeperDone:
			t.Stop()
			return
		case <-t.C:
			f.sweepAllTenants()
			if f.testHook != nil {
				f.testHook()
			}
		}
	}
}

// sweepAllTenants walks every tenant state and evicts idle visitors. The
// TTL defaults to 2x cleanup interval if not configured explicitly.
func (f *Feature) sweepAllTenants() {
	f.mu.RLock()
	states := make([]*tenantState, 0, len(f.tenantBuckets))
	for _, s := range f.tenantBuckets {
		states = append(states, s)
	}
	f.mu.RUnlock()

	now := time.Now()
	for _, st := range states {
		ttl := st.cfg.IdleTTL
		if ttl <= 0 {
			ttl = 2 * st.cfg.CleanupInterval
		}
		if ttl <= 0 {
			ttl = 2 * time.Duration(defaultCleanupSeconds) * time.Second
		}
		cutoff := now.Add(-ttl)
		st.ipBuckets.sweep(cutoff)
		st.apiBuckets.sweep(cutoff)
		// connCounts grows once per unique client IP; without a sweep
		// it leaks ~100 bytes per rotating IPv6 address. We drop any
		// tracker that is currently idle (count == 0) AND has not been
		// touched since the cutoff.
		st.sweepConnCounts(cutoff)
	}
}

// stateFor returns the tenantState for the supplied host, or nil if the
// tenant has no active rate-limit state (disabled / unknown).
func (f *Feature) stateFor(host string) *tenantState {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.tenantBuckets[host]
}

// Middleware returns the http.Handler wrapper for integration with a
// feature.Registry. It adheres to the Feature contract — disabled branches
// are zero-allocation pass-throughs.
func (f *Feature) Middleware(resolver feature.Resolver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !f.enabled.Load() {
				next.ServeHTTP(w, r)
				return
			}
			tenant := feature.TenantFromContext(r.Context())
			if tenant == nil {
				next.ServeHTTP(w, r)
				return
			}
			state := f.stateFor(tenant.Host)
			if state == nil {
				next.ServeHTTP(w, r)
				return
			}
			f.serve(w, r, state, next)
		})
	}
}

// serve performs the actual rate-limit enforcement for a tenant-scoped
// request. It is separated from Middleware so tests can drive it directly.
func (f *Feature) serve(w http.ResponseWriter, r *http.Request, state *tenantState, next http.Handler) {
	// Global-per-tenant limit.
	if !state.globalLimiter.Allow() {
		applyAction(w, r, state.cfg)
		return
	}

	ip := clientIP(r, state.cfg.TrustXFF)

	// Per-IP concurrent-connection cap.
	if state.cfg.PerIPConns > 0 {
		tracker := state.getConnTracker(ip)
		tracker.lastSeen.Store(time.Now().UnixNano())
		if tracker.count.Load() >= int64(state.cfg.PerIPConns) {
			applyAction(w, r, state.cfg)
			return
		}
		tracker.count.Add(1)
		defer func() {
			tracker.count.Add(-1)
			tracker.lastSeen.Store(time.Now().UnixNano())
		}()
	}

	now := time.Now()
	if matchesAnyPrefix(r.URL.Path, state.cfg.APIPathPrefixes) && state.cfg.APIRPS > 0 {
		lim := state.apiBuckets.getOrCreate(ip, now)
		if !lim.Allow() {
			applyAction(w, r, state.cfg)
			return
		}
	} else {
		lim := state.ipBuckets.getOrCreate(ip, now)
		if !lim.Allow() {
			applyAction(w, r, state.cfg)
			return
		}
	}

	next.ServeHTTP(w, r)
}

// getConnTracker lazily allocates a connection counter for ip.
func (s *tenantState) getConnTracker(ip string) *connTracker {
	if v, ok := s.connCounts.Load(ip); ok {
		return v.(*connTracker)
	}
	ct := &connTracker{}
	ct.lastSeen.Store(time.Now().UnixNano())
	actual, _ := s.connCounts.LoadOrStore(ip, ct)
	return actual.(*connTracker)
}

// sweepConnCounts evicts trackers whose count is currently zero and whose
// lastSeen is older than cutoff. Unbounded IPv6 rotation would otherwise
// leak one map entry per unique remote address. Returns the number of
// entries removed; exposed primarily for tests.
func (s *tenantState) sweepConnCounts(cutoff time.Time) int {
	cutoffNano := cutoff.UnixNano()
	removed := 0
	s.connCounts.Range(func(k, v any) bool {
		ct := v.(*connTracker)
		if ct.count.Load() == 0 && ct.lastSeen.Load() < cutoffNano {
			s.connCounts.Delete(k)
			removed++
		}
		return true
	})
	return removed
}

// connCountsSize reports the number of per-IP connection trackers held.
// Test-only helper mirroring limiterCache.size.
func (s *tenantState) connCountsSize() int {
	n := 0
	s.connCounts.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

// matchesAnyPrefix reports whether path starts with any of prefixes,
// case-insensitively. Case folding closes a strict/lenient rate-limit
// split where /API/users bypassed the /api/ prefix and fell back to the
// per-IP limiter (default 30 rps) instead of the stricter api limiter
// (default 5 rps). Upstream routers that normalise case (IIS, servers
// that strings.ToLower before matching) made the mismatch exploitable.
func matchesAnyPrefix(path string, prefixes []string) bool {
	lowered := strings.ToLower(path)
	for _, p := range prefixes {
		if p == "" {
			continue
		}
		if strings.HasPrefix(lowered, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// applyAction serves the configured response when a limit is exceeded.
func applyAction(w http.ResponseWriter, r *http.Request, cfg params) {
	switch cfg.ActionOnExceed {
	case ActionDrop:
		if hij, ok := w.(http.Hijacker); ok {
			conn, _, err := hij.Hijack()
			if err == nil {
				_ = conn.Close()
				return
			}
		}
		// Fall back to a minimal 400 with an empty body; avoids letting
		// the connection complete the response cycle visibly.
		http.Error(w, "", http.StatusBadRequest)
	case ActionTimeout:
		d := cfg.TimeoutOnExceed
		if d <= 0 {
			d = time.Duration(defaultTimeoutSeconds) * time.Second
		}
		// time.After keeps its backing goroutine+timer alive for the
		// full duration even if the select picks ctx.Done first — under
		// rate-limit abuse that leaks memory proportional to req-rate×d.
		// NewTimer+Stop releases the timer immediately on early exit.
		t := time.NewTimer(d)
		select {
		case <-t.C:
		case <-r.Context().Done():
			t.Stop()
		}
		w.Header().Set("Retry-After", "3")
		http.Error(w, "", http.StatusRequestTimeout)
	default: // ActionTooMany and anything unexpected.
		w.Header().Set("Retry-After", "3")
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
	}
}

// clientIP returns the best-effort client IP. Only trusts forwarded
// headers when trustXFF is set; otherwise falls back to RemoteAddr. This
// intentionally differs from internal/proxy/ratelimit.go's
// CF-Connecting-IP reading, which is a local-edge deployment assumption
// not safe in remote mode.
func clientIP(r *http.Request, trustXFF bool) string {
	if trustXFF {
		if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
			return cf
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Take the first hop; XFF is a comma-separated list.
			if idx := strings.IndexByte(xff, ','); idx >= 0 {
				return strings.TrimSpace(xff[:idx])
			}
			return strings.TrimSpace(xff)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
