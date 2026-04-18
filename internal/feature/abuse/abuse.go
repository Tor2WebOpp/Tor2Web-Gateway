package abuse

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gateway/internal/feature"
	"gateway/internal/shared"
)

// FeatureName is the stable identifier used in configuration maps.
const FeatureName = "abuse_api"

// Hard-coded limits. These are not tenant-configurable: the whole point
// of the endpoint is to accept small, structured reports and nothing else.
const (
	maxBodyBytes      = 32 * 1024
	maxOnionMin       = 56
	maxOnionMax       = 58
	maxReasonMin      = 1
	maxReasonMax      = 2000
	maxContactMax     = 200
	maxDetailsMax     = 4000
	defaultRateLimit  = 10
	defaultPath       = "/_abuse"
	rateLimitWindow   = time.Hour
)

// params is the effective configuration for a single tenant (or the
// global fallback). It is populated from a shared.FeatureSnapshot by
// parseParams and is immutable once stored.
type params struct {
	enabled         bool
	path            string
	storePath       string
	notifyEmail     string
	rateLimitPerHr  int
	requireFields   map[string]struct{}
}

// Feature is the abuse_api implementation. It conforms to feature.Feature
// so it can be registered with feature.Registry, and it also exposes a
// plain Middleware function so it can be mounted standalone in tests.
type Feature struct {
	// enabled is true iff any resolved tenant or the globals snapshot has
	// Enabled=true. It is checked cheaply on every request so that the
	// middleware can pass through in the common case.
	enabled atomic.Bool

	mu        sync.RWMutex
	tenantCfg map[string]params // keyed by lowercased host; "" = global
	store     *Store
	limiter   *abuseLimiter

	// salt is a server-local random byte string used to hash client IPs.
	// It is generated on first use and kept in memory only; restarts
	// rotate the salt, which is the desired behaviour (rate limits are
	// ephemeral anyway).
	salt []byte

	// now is injectable for tests; defaults to time.Now.
	now func() time.Time
}

// New constructs a Feature with an empty configuration, a fresh rate
// limiter, and a random hash salt. If storePath is non-empty, the store
// is opened immediately; passing "" leaves store nil (tests set it
// directly via SetStore).
func New(storePath string) (*Feature, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("abuse: generate salt: %w", err)
	}
	f := &Feature{
		tenantCfg: map[string]params{},
		limiter:   newAbuseLimiter(),
		salt:      salt,
		now:       time.Now,
	}
	if storePath != "" {
		s, err := OpenStore(storePath)
		if err != nil {
			return nil, err
		}
		f.store = s
	}
	return f, nil
}

// SetStore replaces the backing store. The previous store is not closed
// by this call; callers that want to rotate should Close the old store
// themselves.
func (f *Feature) SetStore(s *Store) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.store = s
}

// Close closes the backing store if one is open.
func (f *Feature) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.store != nil {
		err := f.store.Close()
		f.store = nil
		return err
	}
	return nil
}

// Name returns the stable feature identifier.
func (f *Feature) Name() string { return FeatureName }

// Validate inspects a candidate snapshot. It accepts any disabled
// snapshot and requires a well-typed path + rate_limit_per_hour when
// enabled.
func (f *Feature) Validate(cfg shared.FeatureSnapshot) error {
	if !cfg.Enabled {
		return nil
	}
	_, err := parseParams(cfg)
	return err
}

// Middleware returns the http.Handler wrapper that intercepts the
// configured abuse path for the current tenant.
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
			p, err := parseParams(snap)
			if err != nil || !p.enabled {
				next.ServeHTTP(w, r)
				return
			}
			// Exact path match only; anything else falls through.
			if r.URL.Path != p.path {
				next.ServeHTTP(w, r)
				return
			}
			tenant := ""
			if t := feature.TenantFromContext(r.Context()); t != nil {
				tenant = strings.ToLower(t.Host)
			}
			f.handle(w, r, tenant, p)
		})
	}
}

// Observe applies a globals snapshot plus every tenant override. It is
// intended to be wired via feature.Registry.AddReloadObserver.
func (f *Feature) Observe(globals feature.GlobalsSnapshot, tenants map[string]feature.TenantSnapshot) {
	f.mu.Lock()
	defer f.mu.Unlock()

	newCfg := make(map[string]params, 1+len(tenants))
	anyEnabled := false

	if gCfg, ok := globals.Features[FeatureName]; ok {
		if p, err := parseParams(gCfg); err == nil {
			newCfg[""] = p
			if p.enabled {
				anyEnabled = true
			}
		}
	}
	for host, tenant := range tenants {
		cfg, ok := tenant.Features[FeatureName]
		if !ok {
			continue
		}
		p, err := parseParams(cfg)
		if err != nil {
			continue
		}
		newCfg[strings.ToLower(host)] = p
		if p.enabled {
			anyEnabled = true
		}
	}

	f.tenantCfg = newCfg
	f.enabled.Store(anyEnabled)
}

// RegisterWith installs f on reg and wires its reload observer. If f is
// nil a new Feature is created with no store attached; the caller is
// responsible for SetStore before enabling the feature.
func RegisterWith(reg *feature.Registry, f *Feature) *Feature {
	if f == nil {
		var err error
		f, err = New("")
		if err != nil {
			// New only fails on crypto/rand error, which would already
			// be fatal for the process. Propagate via panic.
			panic(err)
		}
	}
	reg.Register(f)
	reg.AddReloadObserver(FeatureName, func(_ shared.FeatureSnapshot) {
		f.Observe(reg.Globals(), reg.Tenants())
	})
	return f
}

// -----------------------------------------------------------------------
// Request handling.

// genericValidationMsg is the only body emitted on validation failures.
// Keeping it fixed avoids leaking back what the client sent.
const genericValidationMsg = "invalid request\n"

func (f *Feature) handle(w http.ResponseWriter, r *http.Request, tenant string, p params) {
	// Fixed, minimal headers. No Server header, no caching hints beyond
	// the no-store directive that tells intermediaries not to keep it.
	h := w.Header()
	h["Server"] = nil
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Type", "text/plain; charset=utf-8")

	if r.Method != http.MethodPost {
		h.Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	clientIP := extractClientIP(r)
	ipHash := f.hashIP(clientIP)

	// Rate limit before parsing: we don't want to spend CPU on bodies
	// from a client we are already ignoring.
	limit := p.rateLimitPerHr
	if limit <= 0 {
		limit = defaultRateLimit
	}
	allowed, retryAfter := f.limiter.check(tenant, ipHash, limit, f.now())
	if !allowed {
		if retryAfter > 0 {
			h.Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
		}
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, genericValidationMsg)
		return
	}
	if len(body) > maxBodyBytes {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}

	var report struct {
		Onion   string `json:"onion"`
		Reason  string `json:"reason"`
		Contact string `json:"contact"`
		Details string `json:"details"`
	}
	if err := json.Unmarshal(body, &report); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, genericValidationMsg)
		return
	}
	report.Onion = strings.TrimSpace(report.Onion)
	report.Reason = strings.TrimSpace(report.Reason)
	report.Contact = strings.TrimSpace(report.Contact)

	if err := validateReport(report.Onion, report.Reason, report.Contact, report.Details, p.requireFields); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, genericValidationMsg)
		return
	}

	f.mu.RLock()
	store := f.store
	f.mu.RUnlock()
	if store == nil {
		// Feature enabled but no store wired — treat as server-side
		// misconfiguration; respond with a generic 500 and do not echo.
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	entry := Entry{
		Timestamp:    f.now().UTC(),
		Tenant:       tenant,
		ClientIPHash: ipHash,
		Onion:        report.Onion,
		Reason:       report.Reason,
		Contact:      report.Contact,
		Details:      report.Details,
	}
	if err := store.Append(entry); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// validateReport applies the length limits specified in the design doc
// plus the caller-configured require_fields list. Errors are deliberately
// generic — the caller never leaks which check failed to the HTTP client.
func validateReport(onion, reason, contact, details string, require map[string]struct{}) error {
	if _, ok := require["onion"]; ok && onion == "" {
		return errors.New("onion is required")
	}
	if _, ok := require["reason"]; ok && reason == "" {
		return errors.New("reason is required")
	}
	if _, ok := require["contact"]; ok && contact == "" {
		return errors.New("contact is required")
	}
	if _, ok := require["details"]; ok && details == "" {
		return errors.New("details is required")
	}
	if onion != "" {
		lower := strings.ToLower(onion)
		if !strings.HasSuffix(lower, ".onion") {
			return errors.New("onion must end with .onion")
		}
		// Range check applies to the base32 prefix (the part before
		// ".onion"): v3 addresses are exactly 56 chars; we accept a
		// small slack window to tolerate formatting variations.
		prefix := lower[:len(lower)-len(".onion")]
		l := len(prefix)
		if l < maxOnionMin || l > maxOnionMax {
			return fmt.Errorf("onion length out of range: %d", l)
		}
	}
	if reason != "" {
		l := len(reason)
		if l < maxReasonMin || l > maxReasonMax {
			return fmt.Errorf("reason length out of range: %d", l)
		}
	}
	if len(contact) > maxContactMax {
		return fmt.Errorf("contact too long: %d", len(contact))
	}
	if len(details) > maxDetailsMax {
		return fmt.Errorf("details too long: %d", len(details))
	}
	return nil
}

// hashIP computes sha256(ip + salt) and returns the hex digest.
func (f *Feature) hashIP(ip string) string {
	h := sha256.New()
	h.Write([]byte(ip))
	h.Write(f.salt)
	return hex.EncodeToString(h.Sum(nil))
}

// extractClientIP picks the most trustworthy IP available. The gateway
// terminates TLS itself and proxies upstream; for rate-limit purposes
// RemoteAddr is authoritative. X-Forwarded-For is deliberately ignored
// to prevent a malicious client from rotating keys.
func extractClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// -----------------------------------------------------------------------
// Parameter parsing.

func parseParams(cfg shared.FeatureSnapshot) (params, error) {
	p := params{
		enabled:        cfg.Enabled,
		path:           defaultPath,
		rateLimitPerHr: defaultRateLimit,
		requireFields:  map[string]struct{}{"onion": {}, "reason": {}},
	}
	if cfg.Params == nil {
		return p, nil
	}

	if raw, ok := cfg.Params["path"]; ok {
		s, err := asString(raw, "path")
		if err != nil {
			return params{}, err
		}
		if s == "" {
			return params{}, errors.New("path: must not be empty")
		}
		if !strings.HasPrefix(s, "/") {
			return params{}, fmt.Errorf("path: must start with /, got %q", s)
		}
		p.path = s
	}
	if raw, ok := cfg.Params["store_path"]; ok {
		s, err := asString(raw, "store_path")
		if err != nil {
			return params{}, err
		}
		p.storePath = s
	}
	if raw, ok := cfg.Params["notify_email"]; ok {
		switch v := raw.(type) {
		case nil:
			p.notifyEmail = ""
		case string:
			p.notifyEmail = v
		default:
			return params{}, fmt.Errorf("notify_email: expected string or null, got %T", raw)
		}
	}
	if raw, ok := cfg.Params["rate_limit_per_hour"]; ok {
		n, err := asInt(raw, "rate_limit_per_hour")
		if err != nil {
			return params{}, err
		}
		if n < 0 {
			return params{}, fmt.Errorf("rate_limit_per_hour: must be non-negative, got %d", n)
		}
		p.rateLimitPerHr = int(n)
	}
	if raw, ok := cfg.Params["require_fields"]; ok {
		fields, err := asStringSlice(raw, "require_fields")
		if err != nil {
			return params{}, err
		}
		p.requireFields = map[string]struct{}{}
		for _, name := range fields {
			switch name {
			case "onion", "reason", "contact", "details":
				p.requireFields[name] = struct{}{}
			default:
				return params{}, fmt.Errorf("require_fields: unknown field %q", name)
			}
		}
	}
	return p, nil
}

func asString(v any, field string) (string, error) {
	switch x := v.(type) {
	case string:
		return x, nil
	case nil:
		return "", nil
	default:
		return "", fmt.Errorf("%s: expected string, got %T", field, v)
	}
}

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

func asStringSlice(v any, field string) ([]string, error) {
	switch x := v.(type) {
	case []string:
		out := make([]string, len(x))
		copy(out, x)
		return out, nil
	case []any:
		out := make([]string, len(x))
		for i, e := range x {
			s, err := asString(e, fmt.Sprintf("%s[%d]", field, i))
			if err != nil {
				return nil, err
			}
			out[i] = s
		}
		return out, nil
	case nil:
		return nil, nil
	default:
		return nil, fmt.Errorf("%s: expected list of strings, got %T", field, v)
	}
}

// -----------------------------------------------------------------------
// In-memory rate limiter.

// abuseLimiter is a simple per-(tenant, ip_hash) rolling-1h counter. It
// keeps a bounded list of timestamps per key and trims in place on each
// check. The implementation is deliberately small: real defence against
// sustained flooding lives upstream in the gateway's ratelimit feature.
type abuseLimiter struct {
	mu      sync.Mutex
	windows map[string][]time.Time
}

func newAbuseLimiter() *abuseLimiter {
	return &abuseLimiter{windows: map[string][]time.Time{}}
}

func (l *abuseLimiter) key(tenant, ipHash string) string {
	return tenant + "\x00" + ipHash
}

// check records an attempt at now and returns (allowed, retryAfter). It
// is allowed when the per-key count over the past hour is strictly
// below limit. On deny, retryAfter is the delay until the oldest
// recorded timestamp leaves the window.
func (l *abuseLimiter) check(tenant, ipHash string, limit int, now time.Time) (bool, time.Duration) {
	if limit <= 0 {
		return true, 0
	}
	key := l.key(tenant, ipHash)
	cutoff := now.Add(-rateLimitWindow)

	l.mu.Lock()
	defer l.mu.Unlock()

	hist := l.windows[key]
	// Drop timestamps older than the cutoff.
	i := 0
	for i < len(hist) && hist[i].Before(cutoff) {
		i++
	}
	if i > 0 {
		hist = hist[i:]
	}

	if len(hist) >= limit {
		retry := rateLimitWindow - now.Sub(hist[0])
		if retry < time.Second {
			retry = time.Second
		}
		l.windows[key] = hist
		return false, retry
	}
	hist = append(hist, now)
	l.windows[key] = hist
	return true, 0
}

// ensure interface compliance at compile time.
var _ feature.Feature = (*Feature)(nil)
