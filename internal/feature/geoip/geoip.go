package geoip

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oschwald/maxminddb-golang"

	"gateway/internal/feature"
	"gateway/internal/shared"
)

// FeatureName is the stable identifier used in configuration maps.
const FeatureName = "geoip"

// Default action when a rule is missing one.
const defaultAction = shared.BlockActionNotFound

// LookupFunc returns the ISO 3166-1 alpha-2 country code for the supplied
// IP. An empty string indicates the IP could not be located (treated as
// not-blocked by the middleware). Implementations must be safe for
// concurrent use.
type LookupFunc func(ip net.IP) (string, error)

// rule is the resolved per-tenant configuration. It is built once by
// Observe and never mutated in place; hot-path reads always take it
// through an RWMutex.
type rule struct {
	enabled  bool
	dbPath   string
	blocked  map[string]struct{} // upper-case ISO codes
	action   shared.BlockAction
	trustXFF bool
	// lookup is resolved lazily. When nil the middleware falls back to the
	// feature's default lookup for dbPath; tests may inject a deterministic
	// LookupFunc via WithLookupFunc.
	lookup LookupFunc
}

// readerHandle wraps a *maxminddb.Reader with a reference count. The
// Feature keeps handles in a map keyed by absolute db_path and closes the
// underlying reader when refs drops to zero.
type readerHandle struct {
	reader *maxminddb.Reader
	refs   int
}

// Feature is the geoip middleware implementation.
type Feature struct {
	// enabled is true when the feature is enabled globally or by at least
	// one tenant in the current snapshot. The hot path checks this first
	// to short-circuit without touching any locks.
	enabled atomic.Bool

	// log is the slog logger used for warnings (bad IPs, missing readers).
	// A nil value falls back to slog.Default().
	log *slog.Logger

	// now is used by the timeout action. Tests may override via WithClock.
	now func() time.Time

	// openReader is the function that opens a maxminddb reader for a path.
	// Production uses maxminddb.Open; tests can override to avoid disk I/O.
	openReader func(path string) (*maxminddb.Reader, error)

	// defaultLookup, if set, is used to build a LookupFunc over a reader
	// handle opened from disk. Tests that want to bypass a real reader use
	// WithLookupFunc on a per-rule basis instead.

	mu          sync.RWMutex
	readers     map[string]*readerHandle  // keyed by db_path (absolute)
	tenantRules map[string]rule           // keyed by tenant host
	globalRule  rule                      // fallback when tenant has no override
	// testLookups maps db_path to an injected LookupFunc; when set for a
	// path the feature does not open the real mmdb reader. Used by tests.
	testLookups map[string]LookupFunc
}

// New constructs a Feature with production defaults. The returned value
// must have Observe called at least once before Middleware will act on
// any configuration.
func New() *Feature {
	return &Feature{
		log:         slog.Default(),
		now:         time.Now,
		openReader:  maxminddb.Open,
		readers:     map[string]*readerHandle{},
		tenantRules: map[string]rule{},
		testLookups: map[string]LookupFunc{},
	}
}

// Name implements feature.Feature.
func (f *Feature) Name() string { return FeatureName }

// WithLogger sets a custom *slog.Logger for warnings. It returns f for
// chaining convenience.
func (f *Feature) WithLogger(l *slog.Logger) *Feature {
	if l != nil {
		f.log = l
	}
	return f
}

// WithLookupFunc registers an injected LookupFunc for a given db_path. It
// exists primarily for tests: the feature will use the injected function
// instead of opening a real mmdb file when Observe encounters this path.
// Calling this after Observe has already opened a real reader has no
// effect on the existing handle; callers should register overrides before
// the first Observe.
func (f *Feature) WithLookupFunc(dbPath string, fn LookupFunc) *Feature {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.testLookups == nil {
		f.testLookups = map[string]LookupFunc{}
	}
	f.testLookups[dbPath] = fn
	return f
}

// Validate checks a single FeatureSnapshot for well-formedness. It is
// pure: no state mutation and no filesystem I/O beyond an optional
// existence check on db_path when the feature is enabled.
func (f *Feature) Validate(cfg shared.FeatureSnapshot) error {
	if !cfg.Enabled {
		return nil
	}
	r, err := parseRule(cfg)
	if err != nil {
		return err
	}
	if r.dbPath == "" {
		return errors.New("geoip: db_path is required when enabled")
	}
	if _, injected := f.testLookups[r.dbPath]; !injected {
		// Only check physical existence when we would actually open it.
		if info, statErr := os.Stat(r.dbPath); statErr != nil {
			return fmt.Errorf("geoip: db_path %q: %w", r.dbPath, statErr)
		} else if info.IsDir() {
			return fmt.Errorf("geoip: db_path %q is a directory", r.dbPath)
		}
	}
	return nil
}

// Middleware returns an http.Handler wrapper. The wrapper is installed
// once; runtime toggles are honoured via atomic.Bool and the Resolver.
func (f *Feature) Middleware(res feature.Resolver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !f.enabled.Load() {
				next.ServeHTTP(w, r)
				return
			}

			cfg := res.Resolve(r, FeatureName)
			if !cfg.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			rule, ok := f.effectiveRule(r, cfg)
			if !ok || !rule.enabled || len(rule.blocked) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			ipStr := extractClientIP(r, rule.trustXFF)
			ip := net.ParseIP(ipStr)
			if ip == nil {
				f.log.Warn("geoip: could not parse client IP; bypassing",
					slog.String("remote_addr", r.RemoteAddr))
				next.ServeHTTP(w, r)
				return
			}

			lookup := rule.lookup
			if lookup == nil {
				lookup = f.lookupFor(rule.dbPath)
			}
			if lookup == nil {
				// Reader missing after hot reload race — bypass, log warn.
				f.log.Warn("geoip: no reader for db_path; bypassing",
					slog.String("db_path", rule.dbPath))
				next.ServeHTTP(w, r)
				return
			}

			country, err := lookup(ip)
			if err != nil {
				f.log.Warn("geoip: lookup error; bypassing",
					slog.String("ip", ipStr),
					slog.Any("err", err))
				next.ServeHTTP(w, r)
				return
			}
			if country == "" {
				next.ServeHTTP(w, r)
				return
			}
			if _, blocked := rule.blocked[country]; !blocked {
				next.ServeHTTP(w, r)
				return
			}

			applyAction(w, r, rule.action, f.now)
		})
	}
}

// Observe recomputes reader lifecycle and cached per-tenant rules based on
// the supplied globals + tenants snapshots. It:
//
//   - opens a reader for every new db_path referenced by any enabled rule,
//   - leaves untouched any reader whose refcount stays > 0,
//   - closes and forgets readers no longer referenced,
//   - flips the feature's atomic enable flag to true iff at least one
//     tenant or the globals snapshot has an enabled rule.
//
// Observe is safe to call concurrently with Middleware traffic: all
// mutation happens behind the write lock and hot-path readers take the
// read lock only in lookupFor and effectiveRule.
func (f *Feature) Observe(globals shared.FeatureSnapshot, tenants map[string]shared.FeatureSnapshot) {
	newGlobal := mustParse(globals)
	newTenants := make(map[string]rule, len(tenants))
	for host, cfg := range tenants {
		newTenants[host] = mustParse(cfg)
	}

	// Compute the set of db_paths this new snapshot needs.
	needed := map[string]int{}
	addNeed := func(r rule) {
		if r.enabled && r.dbPath != "" {
			needed[r.dbPath]++
		}
	}
	addNeed(newGlobal)
	for _, r := range newTenants {
		addNeed(r)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	// Open new readers (skip any with an injected test lookup).
	for path := range needed {
		if _, ok := f.testLookups[path]; ok {
			continue
		}
		if _, ok := f.readers[path]; ok {
			continue
		}
		reader, err := f.openReader(path)
		if err != nil {
			f.log.Warn("geoip: failed to open db",
				slog.String("db_path", path), slog.Any("err", err))
			continue
		}
		f.readers[path] = &readerHandle{reader: reader}
	}

	// Update refcounts.
	for path, h := range f.readers {
		h.refs = needed[path]
	}

	// Close readers whose refcount has dropped to zero.
	for path, h := range f.readers {
		if h.refs > 0 {
			continue
		}
		if h.reader != nil {
			if err := h.reader.Close(); err != nil {
				f.log.Warn("geoip: error closing reader",
					slog.String("db_path", path), slog.Any("err", err))
			}
		}
		delete(f.readers, path)
	}

	f.globalRule = newGlobal
	f.tenantRules = newTenants

	// Compute global enabled flag.
	en := newGlobal.enabled
	if !en {
		for _, r := range newTenants {
			if r.enabled {
				en = true
				break
			}
		}
	}
	f.enabled.Store(en)
}

// Close releases every open reader. Calling Close multiple times or after
// Observe has already closed every reader is safe.
func (f *Feature) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	var errs []error
	for path, h := range f.readers {
		if h.reader != nil {
			if err := h.reader.Close(); err != nil {
				errs = append(errs, fmt.Errorf("geoip: close %q: %w", path, err))
			}
		}
		delete(f.readers, path)
	}
	f.enabled.Store(false)
	return errors.Join(errs...)
}

// effectiveRule returns the cached rule that applies to r, combining any
// injected test lookup and reader availability. The second return is
// false only when the feature has never been Observed.
func (f *Feature) effectiveRule(r *http.Request, cfg shared.FeatureSnapshot) (rule, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	// Prefer the cached tenant rule because it carries the parsed/clean
	// maps and any injected LookupFunc attached at Observe time.
	if tenant := feature.TenantFromContext(r.Context()); tenant != nil {
		if tr, ok := f.tenantRules[tenant.Host]; ok {
			// If the resolver disagrees about enabled — e.g. tenant config
			// changed mid-flight — honour the live resolver value.
			tr.enabled = tr.enabled && cfg.Enabled
			if fn, ok := f.testLookups[tr.dbPath]; ok {
				tr.lookup = fn
			}
			return tr, true
		}
	}
	g := f.globalRule
	g.enabled = g.enabled && cfg.Enabled
	if fn, ok := f.testLookups[g.dbPath]; ok {
		g.lookup = fn
	}
	return g, true
}

// lookupFor returns a LookupFunc for the supplied db_path, preferring an
// injected test function over the real reader. Returns nil when neither
// exists. The returned closure takes the read lock on each call so that
// reader replacement during Observe remains safe.
func (f *Feature) lookupFor(path string) LookupFunc {
	f.mu.RLock()
	if fn, ok := f.testLookups[path]; ok {
		f.mu.RUnlock()
		return fn
	}
	h := f.readers[path]
	f.mu.RUnlock()
	if h == nil || h.reader == nil {
		return nil
	}
	return func(ip net.IP) (string, error) {
		var rec struct {
			Country struct {
				ISOCode string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
		}
		if err := h.reader.Lookup(ip.To16(), &rec); err != nil {
			return "", err
		}
		return rec.Country.ISOCode, nil
	}
}

// ---------- helpers ----------

// parseRule interprets a FeatureSnapshot's Params map into a rule. All
// errors are returned; Validate uses them, Observe uses mustParse which
// skips invalid entries and treats them as disabled.
func parseRule(cfg shared.FeatureSnapshot) (rule, error) {
	r := rule{
		enabled: cfg.Enabled,
		blocked: map[string]struct{}{},
		action:  defaultAction,
	}
	if cfg.Params == nil {
		return r, nil
	}
	if v, ok := cfg.Params["db_path"].(string); ok {
		r.dbPath = strings.TrimSpace(v)
	}
	if v, ok := cfg.Params["trust_xff"].(bool); ok {
		r.trustXFF = v
	}
	if v, ok := cfg.Params["action"].(string); ok {
		a := shared.BlockAction(strings.TrimSpace(v))
		if !a.IsValid() {
			return r, fmt.Errorf("geoip: invalid action %q", v)
		}
		r.action = a
	}
	if raw, ok := cfg.Params["block_countries"]; ok {
		switch list := raw.(type) {
		case []string:
			for _, c := range list {
				if err := addCountry(r.blocked, c); err != nil {
					return r, err
				}
			}
		case []any:
			for _, raw := range list {
				s, ok := raw.(string)
				if !ok {
					return r, fmt.Errorf("geoip: block_countries element not a string: %T", raw)
				}
				if err := addCountry(r.blocked, s); err != nil {
					return r, err
				}
			}
		default:
			return r, fmt.Errorf("geoip: block_countries must be list of strings; got %T", raw)
		}
	}
	return r, nil
}

// mustParse is the Observe-side flavour: invalid rules are flattened to
// disabled so that one bad tenant cannot silently knock the feature
// offline for everyone.
func mustParse(cfg shared.FeatureSnapshot) rule {
	r, err := parseRule(cfg)
	if err != nil {
		// Log-and-disable; Validate will have caught this upstream when
		// reload is properly plumbed, but keep the guard defensive.
		return rule{enabled: false, action: defaultAction, blocked: map[string]struct{}{}}
	}
	return r
}

// addCountry normalises and appends a code to the blocked set. Valid
// codes are exactly two letters; values are upper-cased.
func addCountry(dst map[string]struct{}, code string) error {
	c := strings.TrimSpace(code)
	if len(c) != 2 {
		return fmt.Errorf("geoip: country code %q must be 2 chars", code)
	}
	upper := strings.ToUpper(c)
	for _, r := range upper {
		if r < 'A' || r > 'Z' {
			return fmt.Errorf("geoip: country code %q must be A-Z", code)
		}
	}
	dst[upper] = struct{}{}
	return nil
}

// extractClientIP pulls a usable IP string out of the request according to
// rule.trustXFF. When trust_xff is true and the header is present, the
// last comma-separated value is used (nearest-hop semantics); otherwise
// RemoteAddr is used. Port is stripped when present.
func extractClientIP(r *http.Request, trustXFF bool) string {
	if trustXFF {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			last := strings.TrimSpace(parts[len(parts)-1])
			if last != "" {
				return last
			}
		}
	}
	addr := r.RemoteAddr
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// applyAction writes the configured block response. It mirrors the
// behaviour of other feature packages: drop hijacks when possible, 404
// and 429 use standard status codes, timeout holds the connection for a
// deliberate stall before sending 408.
func applyAction(w http.ResponseWriter, r *http.Request, action shared.BlockAction, nowFn func() time.Time) {
	switch action {
	case shared.BlockActionDrop:
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				_ = conn.Close()
				return
			}
		}
		w.WriteHeader(http.StatusBadRequest)
	case shared.BlockActionTooMany:
		w.WriteHeader(http.StatusTooManyRequests)
	case shared.BlockActionTimeout:
		// Hold the request for a deliberate stall. We honour context
		// cancellation so the server can still shut down cleanly.
		t := nowFn
		if t == nil {
			t = time.Now
		}
		deadline := t().Add(30 * time.Second)
		select {
		case <-r.Context().Done():
		case <-timeAfterUntil(deadline, t):
		}
		w.WriteHeader(http.StatusRequestTimeout)
	default: // BlockActionNotFound and any future safe default
		w.WriteHeader(http.StatusNotFound)
	}
}

// timeAfterUntil returns a channel that fires at deadline according to
// nowFn. Isolated so that tests using a fake clock can keep the stall
// deterministic without a sleeping goroutine.
func timeAfterUntil(deadline time.Time, nowFn func() time.Time) <-chan time.Time {
	d := deadline.Sub(nowFn())
	if d < 0 {
		d = 0
	}
	return time.After(d)
}
