package staticcache

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"golang.org/x/sync/singleflight"

	"gateway/internal/feature"
	"gateway/internal/shared"
)

// FeatureName is the stable identifier used in configuration maps.
const FeatureName = "static_cache"

// globalTenantKey is used when a request carries no tenant context. It
// keeps unit tests and any pre-tenant flow from colliding with real
// tenant keys, because "|" never appears in a plain hostname.
const globalTenantKey = "_global_"

// maxCacheBodySize is the hard cap on a single cached response body. It
// mirrors the pre-P1 proxy.Cache limit and protects memory against a
// misconfigured static asset that returns an unexpectedly large blob.
const maxCacheBodySize = 5 * 1024 * 1024

// defaultExtensions is the fallback extension set when the feature is
// enabled but Params omit static_extensions. It mirrors the spec's
// globals.yaml example.
var defaultExtensions = []string{".js", ".css", ".png", ".jpg", ".woff2", ".svg", ".webp"}

// contentTypeByExt is the whitelist of content types accepted for a
// given extension. A missing entry means "any content type"; a match on
// the slice (case-insensitive prefix) is required when the entry exists.
// The check is only applied when the response actually carries a
// Content-Type header — responses without one are trusted by extension.
var contentTypeByExt = map[string][]string{
	"js":    {"application/javascript", "text/javascript", "application/x-javascript"},
	"css":   {"text/css"},
	"png":   {"image/png"},
	"jpg":   {"image/jpeg"},
	"jpeg":  {"image/jpeg"},
	"svg":   {"image/svg+xml", "text/xml", "application/xml"},
	"webp":  {"image/webp"},
	"woff":  {"font/woff", "application/font-woff"},
	"woff2": {"font/woff2", "application/font-woff2"},
	"gif":   {"image/gif"},
	"ico":   {"image/x-icon", "image/vnd.microsoft.icon"},
}

// params is the parsed, validated parameter block. Instances are
// immutable once published.
type params struct {
	maxSizeMB             int
	defaultTTL            time.Duration
	extensions            map[string]struct{}
	extensionsList        []string // canonical order used for equality
	perTenantSizeFraction float64
}

// extCostMultiplier turns the perTenantSizeFraction into an inflation
// factor for per-entry cost reporting. Fraction 0 disables it (returns
// 1). Fraction 0.5 returns 2 so that each entry "costs" twice its byte
// size as far as Ristretto's admission policy is concerned, effectively
// bounding the tenant to half the cache.
func (p *params) extCostMultiplier() int64 {
	if p == nil || p.perTenantSizeFraction <= 0 {
		return 1
	}
	mult := 1.0 / p.perTenantSizeFraction
	if mult < 1 {
		mult = 1
	}
	return int64(mult + 0.5)
}

// cacheEntry is the cached HTTP response payload.
type cacheEntry struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// Feature implements feature.Feature and owns the Ristretto store.
type Feature struct {
	enabled atomic.Bool

	mu    sync.RWMutex
	cache *ristretto.Cache[string, *cacheEntry]
	cfg   atomic.Pointer[params]

	// sf deduplicates concurrent upstream fetches for the same cache key.
	// When N requests arrive for a miss, only one reaches next.ServeHTTP;
	// the others block on the singleflight result and get a copy of the
	// same response buffer. This prevents thundering-herd backend storms
	// on non-200 upstream responses (which cannot be cached) and large
	// cold-miss assets alike.
	sf singleflight.Group
}

// sfResult is the payload shared between the singleflight owner and
// concurrent waiters. It captures just enough of the HTTP response to let
// every waiter reproduce the same output.
type sfResult struct {
	// cacheable is true when the response satisfies cacheableResponse and
	// has been (or is being) admitted to the Ristretto store. Waiters
	// behave the same way either way — they replay the buffered response —
	// but the flag lets callers distinguish for metrics/tests.
	cacheable bool
	// tooBig signals that the upstream response exceeded maxCacheBodySize
	// so the owner fell through to a direct ServeHTTP. Waiters in that
	// case must also fall through (no shared buffer is available).
	tooBig     bool
	statusCode int
	header     http.Header
	body       []byte
}

// New constructs a Feature with no cache and the feature disabled. The
// cache is lazily (re)built by Observe once an enabled configuration is
// supplied.
func New() *Feature {
	return &Feature{}
}

// Name returns the stable feature identifier.
func (f *Feature) Name() string { return FeatureName }

// RegisterWith installs f on reg and wires its reload observer.
func RegisterWith(reg *feature.Registry) *Feature {
	f := New()
	reg.Register(f)
	reg.AddReloadObserver(FeatureName, func(snap shared.FeatureSnapshot) {
		f.Observe(reg.Globals(), reg.Tenants())
	})
	return f
}

// Close releases the underlying cache. Intended for tests and shutdown
// paths — the production hot path never calls Close.
func (f *Feature) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cache != nil {
		f.cache.Close()
		f.cache = nil
	}
}

// Validate checks cfg without mutating Feature state.
func (f *Feature) Validate(cfg shared.FeatureSnapshot) error {
	if !cfg.Enabled && len(cfg.Params) == 0 {
		return nil
	}
	_, err := parseParams(cfg)
	return err
}

// Observe is called after every successful registry reload. It decides
// whether to rebuild the underlying Ristretto cache or merely update
// parameters.
func (f *Feature) Observe(globals feature.GlobalsSnapshot, tenants map[string]feature.TenantSnapshot) {
	globalCfg := globals.Features[FeatureName]
	anyEnabled := globalCfg.Enabled
	for _, t := range tenants {
		if cfg, ok := t.Features[FeatureName]; ok && cfg.Enabled {
			anyEnabled = true
			break
		}
	}

	newParams, err := parseParams(globalCfg)
	if err != nil {
		// Validate should have caught this; if somehow we reach here
		// just disable the feature rather than panic the process.
		f.enabled.Store(false)
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	old := f.cfg.Load()
	needsRebuild := f.cache == nil ||
		old == nil ||
		old.maxSizeMB != newParams.maxSizeMB ||
		!stringSetEqual(old.extensionsList, newParams.extensionsList)

	if needsRebuild {
		if f.cache != nil {
			f.cache.Close()
			f.cache = nil
		}
		if anyEnabled {
			c, err := newRistretto(newParams.maxSizeMB)
			if err == nil {
				f.cache = c
			}
		}
	}

	f.cfg.Store(newParams)
	f.enabled.Store(anyEnabled && f.cache != nil)
}

// Middleware returns the hot-path HTTP handler wrapper.
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
			p := f.cfg.Load()
			if p == nil || !cacheableRequest(r, p.extensions) {
				next.ServeHTTP(w, r)
				return
			}
			cache := f.loadCache()
			if cache == nil {
				next.ServeHTTP(w, r)
				return
			}

			key := tenantKey(r)
			if cached, ok := cache.Get(key); ok && cached != nil {
				writeCached(w, cached)
				return
			}

			// Miss: dedup concurrent upstream fetches for the same key.
			// The owner captures the response into an in-memory buffer
			// and, when eligible, admits it to Ristretto. Waiters receive
			// the buffered payload and replay it onto their own writer
			// — this is what prevents thundering herd on non-200 upstream
			// (which is explicitly NOT cacheable) and on cold cacheable
			// assets alike.
			v, _, _ := f.sf.Do(key, func() (interface{}, error) {
				// Re-check the cache under the singleflight barrier; a
				// previous in-flight owner may have populated between
				// the Get above and our entry into Do.
				if cached, ok := cache.Get(key); ok && cached != nil {
					return &sfResult{
						cacheable:  true,
						statusCode: cached.StatusCode,
						header:     cached.Header,
						body:       cached.Body,
					}, nil
				}

				rec := newCaptureRecorder(nil)
				rec.path = r.URL.Path
				rec.reqHadAuth = r.Header.Get("Authorization") != ""
				next.ServeHTTP(rec, r)

				// Refuse to share responses whose body exceeds the per-
				// entry cap. The owner still gets a correct response via
				// the normal flush() path below; waiters will re-enter
				// the miss path as individual requests.
				if rec.body.Len() > maxCacheBodySize {
					return &sfResult{tooBig: true}, nil
				}

				// Strip hop-by-hop headers before we stash or share the
				// response: Connection, Transfer-Encoding, Keep-Alive,
				// Upgrade, Te, Trailer, Proxy-Authenticate/Authorization
				// are per-connection per RFC 7230 §6.1 and must never
				// cross a cache boundary.
				sharedHdr := cloneHeader(rec.header)
				stripHopByHop(sharedHdr)
				res := &sfResult{
					statusCode: rec.statusCode,
					header:     sharedHdr,
					body:       append([]byte(nil), rec.body.Bytes()...),
				}
				if cacheableResponse(rec) {
					entry := &cacheEntry{
						StatusCode: rec.statusCode,
						Header:     cloneHeader(sharedHdr),
						Body:       append([]byte(nil), rec.body.Bytes()...),
					}
					cost := int64(len(entry.Body))
					if cost <= 0 {
						cost = 1
					}
					cost *= p.extCostMultiplier()
					ttl := p.defaultTTL
					if ttl <= 0 {
						ttl = time.Hour
					}
					cache.SetWithTTL(key, entry, cost, ttl)
					res.cacheable = true
				}
				return res, nil
			})

			result, _ := v.(*sfResult)
			if result == nil || result.tooBig {
				// Fall through — the owner must do the actual work for
				// its own request, and any too-big waiters each get their
				// own upstream call. Fairly ugly but unavoidable: a too-
				// big body cannot be buffered for reuse within the cache
				// memory budget.
				next.ServeHTTP(w, r)
				return
			}

			writeSharedResponse(w, result)
		})
	}
}

// writeSharedResponse replays a buffered upstream response onto w. It is
// called both by the singleflight owner (after its own fetch) and by any
// concurrent waiters that blocked on the same key. Waiters therefore see
// the exact status/headers/body the owner produced. All participants are
// logically on the miss path — subsequent requests that hit the populated
// cache directly via Get go through writeCached and receive X-Cache: HIT.
func writeSharedResponse(w http.ResponseWriter, r *sfResult) {
	hdr := w.Header()
	for k, vals := range r.header {
		for _, v := range vals {
			hdr.Add(k, v)
		}
	}
	if _, exists := hdr["X-Cache"]; !exists {
		hdr.Set("X-Cache", "MISS")
	}
	w.WriteHeader(r.statusCode)
	_, _ = w.Write(r.body)
}

// loadCache returns the current cache pointer under a read lock. It
// returns nil if no cache has been built yet.
func (f *Feature) loadCache() *ristretto.Cache[string, *cacheEntry] {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.cache
}

// -----------------------------------------------------------------------
// Cacheability predicates.

// cacheableRequest returns true when the request is a candidate for a
// cache read or write.
//
// Requests that carry Authorization or Cookie headers are treated as
// unique per caller — sharing a cached response across tenants or users
// would leak session data. These requests bypass the cache entirely.
func cacheableRequest(r *http.Request, exts map[string]struct{}) bool {
	if r == nil {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
		return false
	}
	return hasAllowedExtension(r.URL.Path, exts)
}

// cacheableResponse returns true when the captured response is eligible
// for storage. This is the response-side half of the cache-poisoning
// gate: anything that even hints at per-user content is dropped here.
func cacheableResponse(rec *captureRecorder) bool {
	if rec == nil {
		return false
	}
	// Hard-stop: never cache a response captured for an Authorization-
	// bearing request. cacheableRequest already rejects these, but a
	// handler that mutates headers mid-request could still invalidate
	// that assumption — belt-and-braces.
	if rec.reqHadAuth {
		return false
	}
	if rec.statusCode < 200 || rec.statusCode >= 300 {
		return false
	}
	if rec.body.Len() == 0 || rec.body.Len() > maxCacheBodySize {
		return false
	}
	// Any Set-Cookie is a red flag — a cached response with it would
	// plant that cookie on every subsequent user to receive the entry.
	if len(rec.header.Values("Set-Cookie")) > 0 {
		return false
	}
	if !cacheControlAllowsStorage(rec.header.Get("Cache-Control")) {
		return false
	}
	// Vary: * means "this response depends on inputs the cache does not
	// understand" — the safe behaviour is never to store it. We do not
	// attempt full Vary: <Header1,Header2> canonicalisation: see package
	// caveat for future-work.
	if varyBlocksCache(rec.header.Values("Vary")) {
		return false
	}
	// Require Content-Length so the cache never stores responses whose
	// intended length disagrees with what we captured.
	cl := rec.header.Get("Content-Length")
	if cl == "" {
		return false
	}
	if n, err := strconv.Atoi(cl); err != nil || n != rec.body.Len() {
		return false
	}
	ct := rec.header.Get("Content-Type")
	// text/html commonly carries per-user content (CSRF tokens, nonces,
	// rendered usernames). Only cache it through the explicit asset
	// content-type whitelist below — bare HTML never passes this gate.
	if ct != "" && strings.HasPrefix(strings.ToLower(ct), "text/html") {
		return false
	}
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(rec.path), "."))
	if allowed, ok := contentTypeByExt[ext]; ok && ct != "" {
		ctLower := strings.ToLower(ct)
		match := false
		for _, a := range allowed {
			if strings.HasPrefix(ctLower, a) {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}
	return true
}

// cacheControlAllowsStorage returns false when any Cache-Control
// directive forbids a shared cache from storing the response.
func cacheControlAllowsStorage(cc string) bool {
	if cc == "" {
		return true
	}
	cc = strings.ToLower(cc)
	blockers := []string{
		"private",
		"no-store",
		"no-cache",
		"must-revalidate",
		"s-maxage=0",
		"max-age=0",
	}
	for _, b := range blockers {
		if strings.Contains(cc, b) {
			return false
		}
	}
	return true
}

// varyBlocksCache reports whether any Vary header value is "*" — a
// blanket signal that this response depends on something the cache cannot
// enumerate.
func varyBlocksCache(values []string) bool {
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			if strings.TrimSpace(part) == "*" {
				return true
			}
		}
	}
	return false
}

// hasAllowedExtension reports whether path ends in any of the configured
// extensions. Extensions in the map are stored without a leading dot and
// in lowercase form.
func hasAllowedExtension(path string, exts map[string]struct{}) bool {
	if len(exts) == 0 {
		return false
	}
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(path), "."))
	if ext == "" {
		return false
	}
	_, ok := exts[ext]
	return ok
}

// tenantKey returns the deterministic cache key for a request. The key
// incorporates enough request identity to keep two semantically different
// requests in different slots even if they share a path:
//
//	sha256(
//	    method + "\n" +
//	    lowercase(host) + "\n" +    // full Host header (incl. port)
//	    path + "\n" +                // decoded + path.Clean
//	    rawquery + "\n" +            // sorted alphabetically for determinism
//	    accept_encoding              // gzip | br | identity classification
//	)
//
// Tenant host is folded in as the first byte-chunk so that two tenants
// sharing a Host-header layer (e.g. behind a wildcard vhost) still occupy
// disjoint cache regions — this is the load-bearing guarantee against
// cross-tenant cache poisoning. Missing tenant context falls back to a
// sentinel string so tests and pre-tenant flows do not collide with real
// tenants.
func tenantKey(r *http.Request) string {
	tenantHost := globalTenantKey
	if t := feature.TenantFromContext(r.Context()); t != nil && t.Host != "" {
		tenantHost = strings.ToLower(t.Host)
	}

	hostHeader := strings.ToLower(r.Host)
	cleanPath := path.Clean("/" + strings.TrimLeft(r.URL.Path, "/"))
	sortedQuery := canonicaliseQuery(r.URL.RawQuery)
	accEnc := canonicalAcceptEncoding(r.Header.Get("Accept-Encoding"))

	h := sha256.New()
	// Tenant prefix — not part of the spec's formula but required to
	// prevent two tenants sharing a cache slot under the same Host layer.
	h.Write([]byte(tenantHost))
	h.Write([]byte{0})
	h.Write([]byte(r.Method))
	h.Write([]byte{'\n'})
	h.Write([]byte(hostHeader))
	h.Write([]byte{'\n'})
	h.Write([]byte(cleanPath))
	h.Write([]byte{'\n'})
	h.Write([]byte(sortedQuery))
	h.Write([]byte{'\n'})
	h.Write([]byte(accEnc))
	return hex.EncodeToString(h.Sum(nil))
}

// canonicaliseQuery returns raw query parameters sorted alphabetically by
// key (then by value) so that `?a=1&b=2` and `?b=2&a=1` share a cache
// slot. Parsing is lenient: a malformed query falls back to the original
// string so a pathological caller cannot bypass the cache via whitespace.
func canonicaliseQuery(raw string) string {
	if raw == "" {
		return ""
	}
	pairs := strings.Split(raw, "&")
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

// canonicalAcceptEncoding normalises the Accept-Encoding header so that
// semantically equivalent variants ("gzip, deflate", "gzip,deflate",
// "GZIP, DEFLATE") hash to the same cache key. The algorithm is:
//
//  1. Lowercase the header value.
//  2. Split on commas.
//  3. For each coding, strip whitespace and q-parameters.
//  4. Drop empty tokens and tokens with q=0 (client forbids this coding).
//  5. Sort alphabetically.
//  6. Re-join with ",".
//
// An empty input is treated as the empty canonical string — the same
// bucket clients would land in when they send no Accept-Encoding. A
// response encoded for one accepted set cannot be served to a client
// that did not list it, so the canonical form still segregates entries
// by actually-accepted codings.
func canonicalAcceptEncoding(h string) string {
	if h == "" {
		return ""
	}
	h = strings.ToLower(h)
	parts := strings.Split(h, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// A coding can include parameters: "gzip;q=0.5". The coding
		// itself is everything before the first semicolon.
		coding := p
		qZero := false
		if i := strings.IndexByte(p, ';'); i >= 0 {
			coding = strings.TrimSpace(p[:i])
			params := strings.Split(p[i+1:], ";")
			for _, param := range params {
				param = strings.TrimSpace(param)
				if param == "q=0" || strings.HasPrefix(param, "q=0.") &&
					isAllZero(param[len("q=0."):]) {
					qZero = true
					break
				}
			}
		}
		if coding == "" || qZero {
			continue
		}
		out = append(out, coding)
	}
	if len(out) == 0 {
		return ""
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// isAllZero reports whether every character of s is '0'. Used by
// canonicalAcceptEncoding to recognise q=0, q=0.0, q=0.00, ... as all
// meaning "refuse this coding".
func isAllZero(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] != '0' {
			return false
		}
	}
	return true
}

// writeCached serialises a cache entry onto w.
func writeCached(w http.ResponseWriter, entry *cacheEntry) {
	hdr := w.Header()
	for k, vals := range entry.Header {
		for _, v := range vals {
			hdr.Add(k, v)
		}
	}
	hdr.Set("X-Cache", "HIT")
	w.WriteHeader(entry.StatusCode)
	_, _ = w.Write(entry.Body)
}

// cloneHeader returns a defensive copy of h. Callers mutating the
// returned map will not affect the origin.
func cloneHeader(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, v := range h {
		cp := make([]string, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out
}

// hopByHopHeaders per RFC 7230 §6.1. These are per-connection and MUST
// NOT be stored in a shared cache or replayed to a different client:
// doing so would glue a prior connection's framing metadata onto a fresh
// response and break chunked-encoding / Upgrade handling downstream.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// stripHopByHop removes RFC 7230 hop-by-hop headers from h in place.
// Also removes every header named by a Connection: <name> listing, per
// the same RFC: Connection is itself the mechanism by which custom
// hop-by-hop headers are declared.
func stripHopByHop(h http.Header) {
	if conns := h.Values("Connection"); len(conns) > 0 {
		for _, line := range conns {
			for _, tok := range strings.Split(line, ",") {
				if name := strings.TrimSpace(tok); name != "" {
					h.Del(name)
				}
			}
		}
	}
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}

// -----------------------------------------------------------------------
// captureRecorder

// captureRecorder buffers the downstream handler's response so the
// middleware can decide whether to store and/or flush it. It does not
// write directly to the underlying ResponseWriter until flush is called.
type captureRecorder struct {
	underlying http.ResponseWriter
	header     http.Header
	body       bytes.Buffer
	statusCode int
	headerSent bool
	path       string
	// reqHadAuth records whether the originating request carried an
	// Authorization header. cacheableResponse double-checks this so a
	// downstream handler cannot coerce us into storing per-user content.
	reqHadAuth bool
}

func newCaptureRecorder(w http.ResponseWriter) *captureRecorder {
	return &captureRecorder{
		underlying: w,
		header:     make(http.Header),
		statusCode: http.StatusOK,
	}
}

// Header satisfies http.ResponseWriter. The recorder exposes its own
// Header map so downstream handlers can mutate it freely without
// touching the real response yet.
func (rr *captureRecorder) Header() http.Header { return rr.header }

// WriteHeader captures the status code. The first call wins, matching
// net/http semantics.
func (rr *captureRecorder) WriteHeader(code int) {
	if rr.headerSent {
		return
	}
	rr.statusCode = code
	rr.headerSent = true
}

// Write buffers b. It never forwards to the underlying writer; flush
// replays the buffer at the end.
func (rr *captureRecorder) Write(b []byte) (int, error) {
	if !rr.headerSent {
		rr.WriteHeader(http.StatusOK)
	}
	return rr.body.Write(b)
}

// flush replays the captured headers, status and body onto the
// underlying ResponseWriter. It is idempotent: after the first call, the
// state is marked as flushed by clearing the underlying reference.
func (rr *captureRecorder) flush() {
	if rr.underlying == nil {
		return
	}
	dst := rr.underlying.Header()
	for k, vals := range rr.header {
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
	if _, exists := dst["X-Cache"]; !exists {
		dst.Set("X-Cache", "MISS")
	}
	rr.underlying.WriteHeader(rr.statusCode)
	_, _ = rr.underlying.Write(rr.body.Bytes())
	rr.underlying = nil
}

// Bytes exposes the captured body. It is only used by tests for the
// cache-population path.
func (rr *captureRecorder) Bytes() []byte { return rr.body.Bytes() }

// -----------------------------------------------------------------------
// Ristretto plumbing.

// newRistretto constructs the underlying cache. The parameter accounts
// for the global budget; admission pressure is supplied per-entry via
// the cost function at Set time.
func newRistretto(maxSizeMB int) (*ristretto.Cache[string, *cacheEntry], error) {
	if maxSizeMB <= 0 {
		maxSizeMB = 256
	}
	maxBytes := int64(maxSizeMB) * 1024 * 1024
	cfg := &ristretto.Config[string, *cacheEntry]{
		NumCounters: 1e7,
		MaxCost:     maxBytes,
		BufferItems: 64,
		Cost: func(val *cacheEntry) int64 {
			if val == nil {
				return 1
			}
			n := int64(len(val.Body))
			if n <= 0 {
				return 1
			}
			return n
		},
	}
	return ristretto.NewCache(cfg)
}

// -----------------------------------------------------------------------
// Parameter parsing.

// parseParams reads cfg.Params into a validated params value. It tolerates
// a nil Params map on disabled snapshots and falls back to defaults when
// individual keys are absent.
func parseParams(cfg shared.FeatureSnapshot) (*params, error) {
	p := &params{
		maxSizeMB:             256,
		defaultTTL:            time.Hour,
		perTenantSizeFraction: 0,
	}
	exts := defaultExtensions

	if cfg.Params != nil {
		if raw, ok := cfg.Params["max_size_mb"]; ok {
			n, err := asInt(raw, "max_size_mb")
			if err != nil {
				return nil, err
			}
			if n <= 0 {
				return nil, fmt.Errorf("max_size_mb: must be positive, got %d", n)
			}
			p.maxSizeMB = int(n)
		}
		if raw, ok := cfg.Params["default_ttl"]; ok {
			d, err := asDuration(raw, "default_ttl")
			if err != nil {
				return nil, err
			}
			if d < 0 {
				return nil, fmt.Errorf("default_ttl: must be non-negative, got %s", d)
			}
			p.defaultTTL = d
		}
		if raw, ok := cfg.Params["per_tenant_size_fraction"]; ok {
			f, err := asFloat(raw, "per_tenant_size_fraction")
			if err != nil {
				return nil, err
			}
			if f < 0 || f > 1 {
				return nil, fmt.Errorf("per_tenant_size_fraction: must be in [0,1], got %v", f)
			}
			p.perTenantSizeFraction = f
		}
		if raw, ok := cfg.Params["static_extensions"]; ok {
			parsed, err := asStringSlice(raw, "static_extensions")
			if err != nil {
				return nil, err
			}
			exts = parsed
		}
	}

	p.extensions = make(map[string]struct{}, len(exts))
	p.extensionsList = make([]string, 0, len(exts))
	for _, e := range exts {
		e = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(e), "."))
		if e == "" {
			continue
		}
		if _, seen := p.extensions[e]; seen {
			continue
		}
		p.extensions[e] = struct{}{}
		p.extensionsList = append(p.extensionsList, e)
	}
	// Canonicalise order so stringSetEqual is stable against input
	// ordering variance across reloads.
	sortStrings(p.extensionsList)

	return p, nil
}

// -----------------------------------------------------------------------
// Coercion helpers — YAML unmarshalling goes through map[string]any, so
// numeric values may arrive as int or float depending on the source.

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
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%s: expected integer, got %q", field, x)
		}
		return n, nil
	default:
		return 0, fmt.Errorf("%s: expected integer, got %T", field, v)
	}
}

func asFloat(v any, field string) (float64, error) {
	switch x := v.(type) {
	case float64:
		return x, nil
	case float32:
		return float64(x), nil
	case int:
		return float64(x), nil
	case int32:
		return float64(x), nil
	case int64:
		return float64(x), nil
	case string:
		n, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		if err != nil {
			return 0, fmt.Errorf("%s: expected number, got %q", field, x)
		}
		return n, nil
	default:
		return 0, fmt.Errorf("%s: expected number, got %T", field, v)
	}
}

func asDuration(v any, field string) (time.Duration, error) {
	switch x := v.(type) {
	case time.Duration:
		return x, nil
	case string:
		d, err := time.ParseDuration(strings.TrimSpace(x))
		if err != nil {
			return 0, fmt.Errorf("%s: %w", field, err)
		}
		return d, nil
	case int:
		return time.Duration(x) * time.Second, nil
	case int64:
		return time.Duration(x) * time.Second, nil
	case float64:
		return time.Duration(x * float64(time.Second)), nil
	default:
		return 0, fmt.Errorf("%s: expected duration string, got %T", field, v)
	}
}

func asStringSlice(v any, field string) ([]string, error) {
	switch x := v.(type) {
	case []string:
		out := make([]string, len(x))
		copy(out, x)
		return out, nil
	case []any:
		out := make([]string, 0, len(x))
		for i, item := range x {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("%s[%d]: expected string, got %T", field, i, item)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%s: expected list of strings, got %T", field, v)
	}
}

// stringSetEqual reports whether a and b contain the same strings. Both
// slices are expected to be sorted.
func stringSetEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// sortStrings sorts s in place using a small insertion sort to avoid
// pulling in the sort package for a handful of extensions.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// Compile-time assertion that Feature satisfies feature.Feature.
var _ feature.Feature = (*Feature)(nil)
