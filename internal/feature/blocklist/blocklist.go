package blocklist

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gateway/internal/feature"
	"gateway/internal/shared"
)

// FeatureName is the stable identifier used in configuration maps.
const FeatureName = "blocklist_regex"

// globalTenantKey is the pseudo-host used for the rule set that applies
// when a request has no tenant context (or the tenant has no override).
const globalTenantKey = "_global_"

// defaultTimeout is the sleep duration applied to the timeout action when
// no per-snapshot override is supplied.
const defaultTimeout = 30 * time.Second

// compiledPattern is a validated pattern: a compiled regex bound to an
// action to apply on a match. Target selects what string the regex runs
// against (path is the default; reserved for header matching per spec).
type compiledPattern struct {
	re     *regexp.Regexp
	action shared.BlockAction
	// target is reserved for future per-spec header matching; in P1 the
	// package only exercises path matching, and target is always "path".
	target string
	// header is populated when target == "header" and names the header to
	// consult. Unused in P1 but wired so that the match loop is ready.
	header string
}

// tenantRules is the immutable, pre-compiled rule set for one tenant (or
// the global fallback). The zero value represents "no rules" and returns
// nil from Match.
type tenantRules struct {
	patterns      []compiledPattern
	defaultAction shared.BlockAction
	timeout       time.Duration
}

// Match walks patterns in declaration order; first match wins. It returns
// the matching pattern or nil when no pattern applies.
func (tr *tenantRules) Match(r *http.Request) *compiledPattern {
	if tr == nil || len(tr.patterns) == 0 {
		return nil
	}
	path := r.URL.Path
	for i := range tr.patterns {
		p := &tr.patterns[i]
		subject := path
		switch p.target {
		case "header":
			if p.header == "" {
				continue
			}
			subject = r.Header.Get(p.header)
			if subject == "" {
				continue
			}
		default:
			subject = path
		}
		if p.re.MatchString(subject) {
			return p
		}
	}
	return nil
}

// Feature is the blocklist_regex implementation. It plugs into the
// feature.Registry and swaps its compiled rule set atomically on reload.
type Feature struct {
	// enabled is set in Observe: true iff any resolved snapshot (globals
	// or any tenant override) has Enabled=true. Middleware consults this
	// flag cheaply before any further work.
	enabled atomic.Bool

	// compiled is a pointer-swappable map of pre-compiled rules. It is
	// rebuilt on every Observe call and published atomically; readers
	// never mutate the map they receive.
	compiled atomic.Pointer[map[string]*tenantRules]

	// mu guards Observe itself so that concurrent reloads do not race on
	// compilation work, though only the atomic store is visible to
	// readers.
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

// Validate compiles every regex and checks every action in cfg without
// mutating Feature state. Called by the registry for both globals and
// every tenant override prior to any swap.
func (f *Feature) Validate(cfg shared.FeatureSnapshot) error {
	// A disabled snapshot with no params is always valid — nothing to do.
	if !cfg.Enabled && len(cfg.Params) == 0 {
		return nil
	}
	// Perform the full compile to surface regex errors too. The compiled
	// output is discarded because Validate must not mutate state.
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
			if t := feature.TenantFromContext(r.Context()); t != nil && t.Host != "" {
				tenantKey = strings.ToLower(t.Host)
			}
			rules := f.rulesFor(tenantKey)
			if rules == nil {
				next.ServeHTTP(w, r)
				return
			}
			m := rules.Match(r)
			if m == nil {
				next.ServeHTTP(w, r)
				return
			}
			action := m.action
			if action == "" {
				action = rules.defaultAction
			}
			if action == "" {
				action = shared.BlockActionDrop
			}
			f.respond(w, r, action, rules.timeout)
		})
	}
}

// Observe installs a newly-validated configuration. Called once per
// registry reload cycle with the effective globals snapshot plus every
// tenant snapshot — the hub always emits the full picture, so a full
// rebuild is cheaper than incremental reconciliation and keeps Observe
// idempotent.
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
// global fallback when the tenant has no explicit entry. Returns nil when
// neither is present.
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

// respond applies the selected block action against w. The response is
// final — no call to next.ServeHTTP follows.
func (f *Feature) respond(w http.ResponseWriter, r *http.Request, action shared.BlockAction, timeout time.Duration) {
	switch action {
	case shared.BlockActionNotFound:
		w.WriteHeader(http.StatusNotFound)
	case shared.BlockActionTooMany:
		w.WriteHeader(http.StatusTooManyRequests)
	case shared.BlockActionTimeout:
		sleep := timeout
		if sleep <= 0 {
			sleep = defaultTimeout
		}
		// Respect request cancellation so tests and production never
		// block beyond the client's patience window.
		ctx := r.Context()
		t := time.NewTimer(sleep)
		defer t.Stop()
		select {
		case <-t.C:
		case <-ctx.Done():
		}
		hijackAndClose(w)
	case shared.BlockActionDrop:
		hijackAndClose(w)
	default:
		// Unknown action should never reach here because Validate
		// refuses bad actions, but close defensively.
		hijackAndClose(w)
	}
}

// hijackAndClose takes over the underlying TCP connection and closes it
// without writing a response. When hijacking is not supported by the
// ResponseWriter (e.g. httptest.ResponseRecorder, HTTP/2), it falls back
// to an empty 400 — a deliberately mute signal that conveys "rejected"
// without leaking any diagnostic body.
func hijackAndClose(w http.ResponseWriter) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	_ = conn.Close()
}

// RegisterWith installs f on reg and wires its reload observer. A new
// Feature is created if f is nil, matching the convenience pattern used
// elsewhere in the gateway.
func RegisterWith(reg *feature.Registry) *Feature {
	f := New()
	reg.Register(f)
	reg.AddReloadObserver(FeatureName, func(snap shared.FeatureSnapshot) {
		// The observer receives only the globals snapshot for this
		// feature. Full state including tenant overrides is read
		// directly from reg so Observe sees the same view as the
		// registry just published.
		f.Observe(reg.Globals(), reg.Tenants())
	})
	return f
}

// -----------------------------------------------------------------------
// Configuration parsing and compilation.

// parsedRule is the intermediate representation produced by parseRules.
// It is only used during Validate/compile and never escapes to the hot
// path.
type parsedRule struct {
	pattern string
	action  shared.BlockAction
	target  string
	header  string
}

// parseRules deserialises a FeatureSnapshot's Params into a slice of
// parsedRule plus a default action. It performs every validation the
// Feature can without compiling the regexes (those errors surface during
// compileCfg). parseRules is tolerant of an absent Params map on disabled
// snapshots.
func parseRules(cfg shared.FeatureSnapshot) ([]parsedRule, shared.BlockAction, time.Duration, error) {
	var defAction shared.BlockAction
	timeout := time.Duration(0)

	if cfg.Params == nil {
		if cfg.Enabled {
			// Enabled with no params is legal: no patterns means no
			// matches, which is a no-op. Keep it permissive.
			return nil, defAction, timeout, nil
		}
		return nil, defAction, timeout, nil
	}

	if raw, ok := cfg.Params["default_action"]; ok {
		s, err := asString(raw, "default_action")
		if err != nil {
			return nil, "", 0, err
		}
		a := shared.BlockAction(s)
		if !a.IsValid() {
			return nil, "", 0, fmt.Errorf("default_action %q: not a valid BlockAction", s)
		}
		defAction = a
	}

	if raw, ok := cfg.Params["timeout_seconds"]; ok {
		n, err := asInt(raw, "timeout_seconds")
		if err != nil {
			return nil, "", 0, err
		}
		if n < 0 {
			return nil, "", 0, fmt.Errorf("timeout_seconds: must be non-negative, got %d", n)
		}
		timeout = time.Duration(n) * time.Second
	}

	patternsRaw, ok := cfg.Params["patterns"]
	if !ok {
		return nil, defAction, timeout, nil
	}

	patternsSlice, ok := patternsRaw.([]any)
	if !ok {
		// YAML unmarshalling via yaml.v3 uses []interface{} for
		// sequences, but the caller may have normalised to []map[string]any.
		if alt, altOk := patternsRaw.([]map[string]any); altOk {
			patternsSlice = make([]any, len(alt))
			for i, m := range alt {
				patternsSlice[i] = m
			}
		} else {
			return nil, "", 0, fmt.Errorf("patterns: expected list, got %T", patternsRaw)
		}
	}

	rules := make([]parsedRule, 0, len(patternsSlice))
	for i, entry := range patternsSlice {
		m, ok := entry.(map[string]any)
		if !ok {
			return nil, "", 0, fmt.Errorf("patterns[%d]: expected map, got %T", i, entry)
		}
		pr, err := parseOne(i, m, defAction)
		if err != nil {
			return nil, "", 0, err
		}
		rules = append(rules, pr)
	}

	return rules, defAction, timeout, nil
}

// parseOne extracts a single rule entry. It validates that action, when
// present, names a BlockAction. When action is absent and no default is
// set, it is still permitted so long as the feature exposes something
// meaningful at match time — compileCfg ensures a fallback.
func parseOne(i int, m map[string]any, def shared.BlockAction) (parsedRule, error) {
	patternRaw, ok := m["pattern"]
	if !ok {
		return parsedRule{}, fmt.Errorf("patterns[%d]: missing pattern", i)
	}
	pattern, err := asString(patternRaw, fmt.Sprintf("patterns[%d].pattern", i))
	if err != nil {
		return parsedRule{}, err
	}
	if pattern == "" {
		return parsedRule{}, fmt.Errorf("patterns[%d]: pattern is empty", i)
	}

	var action shared.BlockAction
	if raw, ok := m["action"]; ok {
		s, err := asString(raw, fmt.Sprintf("patterns[%d].action", i))
		if err != nil {
			return parsedRule{}, err
		}
		a := shared.BlockAction(s)
		if !a.IsValid() {
			return parsedRule{}, fmt.Errorf("patterns[%d].action %q: not a valid BlockAction", i, s)
		}
		action = a
	} else if def == "" {
		return parsedRule{}, fmt.Errorf("patterns[%d]: action missing and no default_action set", i)
	}

	target := "path"
	if raw, ok := m["target"]; ok {
		s, err := asString(raw, fmt.Sprintf("patterns[%d].target", i))
		if err != nil {
			return parsedRule{}, err
		}
		switch s {
		case "path", "header":
			target = s
		case "":
			target = "path"
		default:
			return parsedRule{}, fmt.Errorf("patterns[%d].target %q: must be path or header", i, s)
		}
	}

	header := ""
	if raw, ok := m["header"]; ok {
		s, err := asString(raw, fmt.Sprintf("patterns[%d].header", i))
		if err != nil {
			return parsedRule{}, err
		}
		header = s
	}
	if target == "header" && header == "" {
		return parsedRule{}, fmt.Errorf("patterns[%d]: target=header requires header name", i)
	}

	return parsedRule{pattern: pattern, action: action, target: target, header: header}, nil
}

// compileCfg turns a FeatureSnapshot into a tenantRules ready for the
// hot path. It first delegates to parseRules (so every diagnostic from
// Validate surfaces here too) and then compiles each regex.
func compileCfg(cfg shared.FeatureSnapshot) (*tenantRules, error) {
	parsed, defAction, timeout, err := parseRules(cfg)
	if err != nil {
		return nil, err
	}
	if !cfg.Enabled && len(parsed) == 0 {
		return nil, nil
	}
	rules := &tenantRules{
		defaultAction: defAction,
		timeout:       timeout,
	}
	if len(parsed) == 0 {
		return rules, nil
	}
	rules.patterns = make([]compiledPattern, 0, len(parsed))
	for i, pr := range parsed {
		re, err := regexp.Compile(pr.pattern)
		if err != nil {
			return nil, fmt.Errorf("patterns[%d] %q: %w", i, pr.pattern, err)
		}
		rules.patterns = append(rules.patterns, compiledPattern{
			re:     re,
			action: pr.action,
			target: pr.target,
			header: pr.header,
		})
	}
	return rules, nil
}

// asString coerces common YAML scalar types to string. yaml.v3 normally
// unmarshals strings as string, but numeric-looking values may arrive as
// int/float from other paths; accept both.
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

// asInt coerces common YAML numeric types to int64.
func asInt(v any, field string) (int64, error) {
	switch x := v.(type) {
	case int:
		return int64(x), nil
	case int32:
		return int64(x), nil
	case int64:
		return x, nil
	case uint:
		return int64(x), nil
	case uint32:
		return int64(x), nil
	case uint64:
		return int64(x), nil
	case float32:
		return int64(x), nil
	case float64:
		return int64(x), nil
	default:
		return 0, fmt.Errorf("%s: expected integer, got %T", field, v)
	}
}

// ensure interface compliance at compile time.
var _ feature.Feature = (*Feature)(nil)

// Guard against accidentally shadowing the errors import if this file is
// ever edited to drop uses.
var _ = errors.New
