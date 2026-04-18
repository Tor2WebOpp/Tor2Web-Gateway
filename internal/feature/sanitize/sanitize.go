package sanitize

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/net/html"

	"gateway/internal/feature"
	"gateway/internal/shared"
)

// FeatureName is the stable identifier used in configuration maps and in
// logs. Changing it is a breaking runtime-config change.
const FeatureName = "content_sanitizer"

// globalTenantKey is the pseudo-host used for the policy that applies when
// a request has no tenant context (or the tenant has no override).
const globalTenantKey = "_global_"

// defaultMaxBody is the cap applied when a snapshot does not supply one.
// 8 MiB is generous for HTML responses and small enough to bound worst
// case memory per in-flight request.
const defaultMaxBody int64 = 8 * 1024 * 1024

// defaultStripTags is the list the spec hard-codes as the safe starting
// point. All comparisons in the hot path happen against lowercased names.
var defaultStripTags = []string{
	"script", "object", "embed", "iframe",
	"link", "meta", "form", "input",
}

// defaultStripAttrPatterns is the list the spec hard-codes. Each entry is
// treated either as a literal attribute key (e.g. "onclick") or as a
// case-insensitive substring match against the attribute's unescaped value
// (e.g. "javascript:" matches href="JavaScript:alert(1)").
var defaultStripAttrPatterns = []string{
	"onclick", "onload", "onerror", "javascript:",
}

// defaultContentTypes is the list used when content_types is absent.
var defaultContentTypes = []string{"text/html"}

// voidElements is the HTML5 set of elements that must not have closing
// tags. The tokenizer reports them as StartTagToken (not
// SelfClosingTagToken) so our skip logic needs to treat a strip-match on
// one of these as a self-contained delete rather than entering a
// "waiting for end tag" state that would swallow the rest of the
// document.
var voidElements = map[string]struct{}{
	"area":    {},
	"base":    {},
	"br":      {},
	"col":     {},
	"embed":   {},
	"hr":      {},
	"img":     {},
	"input":   {},
	"link":    {},
	"meta":    {},
	"param":   {},
	"source":  {},
	"track":   {},
	"wbr":     {},
	"keygen":  {},
	"command": {},
}

func isVoid(name string) bool {
	_, ok := voidElements[name]
	return ok
}

// policy is the immutable, pre-parsed configuration for one tenant (or
// the global fallback). The zero value represents "do nothing".
type policy struct {
	enabled      bool
	stripTags    map[string]struct{} // lowercased tag names
	stripAttrs   []string            // lowercased key / value substrings
	contentTypes []string            // lowercased, trimmed media-type prefixes
	maxBody      int64
}

// Match returns true when ct, interpreted as a full Content-Type header
// value, has a media type matching one of the policy's content_types.
func (p *policy) matchesContentType(ct string) bool {
	if p == nil || len(p.contentTypes) == 0 {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		// Fall back to a simple prefix match on whatever came in; the
		// Content-Type header may be malformed but we still want to scan
		// obvious HTML payloads.
		mediaType = strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	} else {
		mediaType = strings.ToLower(mediaType)
	}
	if mediaType == "" {
		return false
	}
	for _, want := range p.contentTypes {
		if mediaType == want || strings.HasPrefix(mediaType, want) {
			return true
		}
	}
	return false
}

// shouldStripTag reports whether name (expected lowercased) is in the
// configured strip list. Case folding is caller's responsibility.
func (p *policy) shouldStripTag(name string) bool {
	if p == nil || len(p.stripTags) == 0 {
		return false
	}
	_, ok := p.stripTags[name]
	return ok
}

// shouldStripAttr reports whether an attribute key/value pair matches any
// of the configured strip_attributes entries. key and val are expected
// lowercased already.
func (p *policy) shouldStripAttr(key, val string) bool {
	if p == nil || len(p.stripAttrs) == 0 {
		return false
	}
	for _, pat := range p.stripAttrs {
		if pat == "" {
			continue
		}
		if key == pat {
			return true
		}
		if val != "" && strings.Contains(val, pat) {
			return true
		}
	}
	return false
}

// Feature is the content_sanitizer implementation. It plugs into the
// feature.Registry and swaps its per-tenant policy map atomically on
// reload.
type Feature struct {
	// enabled is set in Observe: true iff any resolved snapshot (globals
	// or any tenant override) has Enabled=true. Middleware consults this
	// flag cheaply before any further work.
	enabled atomic.Bool

	// compiled is the pointer-swappable map of policies keyed by
	// lowercased tenant host (plus the globalTenantKey). Every Observe
	// call publishes a new map; readers never mutate the map they load.
	compiled atomic.Pointer[map[string]*policy]

	// mu guards Observe so that concurrent reloads do not race on the
	// parse/compile work. Only the atomic store is visible to readers.
	mu sync.Mutex

	// logger is used for body-cap warnings. Nil means slog.Default().
	logger *slog.Logger
}

// New constructs a Feature with an empty policy map and disabled flag.
func New() *Feature {
	f := &Feature{}
	empty := map[string]*policy{}
	f.compiled.Store(&empty)
	return f
}

// Name returns the stable feature identifier.
func (f *Feature) Name() string { return FeatureName }

// SetLogger installs a custom slog.Logger for body-cap warnings. A nil
// argument resets the feature to slog.Default().
func (f *Feature) SetLogger(l *slog.Logger) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logger = l
}

// Validate parses cfg and reports any structural errors without mutating
// Feature state. It is called by the registry for globals and every
// tenant override prior to any swap.
func (f *Feature) Validate(cfg shared.FeatureSnapshot) error {
	// A disabled snapshot with no params is always valid.
	if !cfg.Enabled && len(cfg.Params) == 0 {
		return nil
	}
	_, err := compileCfg(cfg)
	return err
}

// Middleware returns the response-sanitizing handler. Built once; live
// toggling happens via the atomic.Pointer swap in Observe.
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
			pol := f.policyFor(r)
			if pol == nil || !pol.enabled {
				next.ServeHTTP(w, r)
				return
			}

			rec := newRecorderWith(w, r.Method, pol.maxBody)
			next.ServeHTTP(rec, r)
			f.finish(w, rec, pol)
		})
	}
}

// policyFor selects the policy for the tenant attached to r. Falls back
// to the global policy when no override exists.
func (f *Feature) policyFor(r *http.Request) *policy {
	p := f.compiled.Load()
	if p == nil {
		return nil
	}
	m := *p
	if t := feature.TenantFromContext(r.Context()); t != nil && t.Host != "" {
		if pol, ok := m[strings.ToLower(t.Host)]; ok {
			return pol
		}
	}
	if pol, ok := m[globalTenantKey]; ok {
		return pol
	}
	return nil
}

// finish writes the buffered response to the real ResponseWriter,
// sanitizing it when appropriate.
func (f *Feature) finish(w http.ResponseWriter, rec *recorder, pol *policy) {
	ct := rec.header.Get("Content-Type")
	sanitize := pol.matchesContentType(ct)

	// If the body was capped off because the handler wrote more than the
	// policy allows, we always pass the body through — sanitizing a
	// truncated HTML stream could make it worse.
	if sanitize && rec.overflowed {
		f.log().Warn("content_sanitizer: body exceeded max_body_bytes, passing through unchanged",
			slog.Int64("max_body_bytes", pol.maxBody),
			slog.Int64("body_bytes_seen", rec.totalBytes),
		)
		sanitize = false
	}

	body := rec.buf.Bytes()
	if sanitize {
		out, err := sanitizeHTML(body, pol)
		if err != nil {
			// Tokenizer errors other than io.EOF should be rare; when they
			// surface we fail open (pass original) rather than serving a
			// half-rewritten response. Log once and move on.
			f.log().Warn("content_sanitizer: tokenizer error, passing through unchanged",
				slog.String("err", err.Error()),
			)
		} else {
			body = out
			// Content-Length is now inaccurate; strip it so Go's server
			// falls back to chunked-transfer.
			rec.header.Del("Content-Length")
		}
	}

	// Replay captured headers onto the real writer.
	dst := w.Header()
	for k, vs := range rec.header {
		dst[k] = vs
	}
	status := rec.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	if len(body) > 0 && rec.method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

func (f *Feature) log() *slog.Logger {
	if f.logger != nil {
		return f.logger
	}
	return slog.Default()
}

// Observe installs a newly-validated configuration. Invoked once per
// reload cycle with the effective globals snapshot plus every tenant's
// snapshot.
func (f *Feature) Observe(globals feature.GlobalsSnapshot, tenants map[string]feature.TenantSnapshot) {
	f.mu.Lock()
	defer f.mu.Unlock()

	newMap := make(map[string]*policy, 1+len(tenants))
	anyEnabled := false

	globalCfg := globals.Features[FeatureName]
	if pol, err := compileCfg(globalCfg); err == nil && pol != nil {
		newMap[globalTenantKey] = pol
		if pol.enabled {
			anyEnabled = true
		}
	}

	for host, tenant := range tenants {
		cfg, ok := tenant.Features[FeatureName]
		if !ok {
			continue
		}
		pol, err := compileCfg(cfg)
		if err != nil || pol == nil {
			continue
		}
		newMap[strings.ToLower(host)] = pol
		if pol.enabled {
			anyEnabled = true
		}
	}

	f.compiled.Store(&newMap)
	f.enabled.Store(anyEnabled)
}

// RegisterWith installs a fresh Feature on reg and wires its reload
// observer. Returns the Feature so callers (tests or composition code)
// can access it.
func RegisterWith(reg *feature.Registry) *Feature {
	f := New()
	reg.Register(f)
	reg.AddReloadObserver(FeatureName, func(snap shared.FeatureSnapshot) {
		f.Observe(reg.Globals(), reg.Tenants())
	})
	return f
}

// -----------------------------------------------------------------------
// Configuration parsing.

// compileCfg turns a FeatureSnapshot into a *policy ready for the hot
// path. Returns (nil, nil) when the snapshot is disabled and carries no
// parameters — callers treat this as "no entry".
func compileCfg(cfg shared.FeatureSnapshot) (*policy, error) {
	if !cfg.Enabled && len(cfg.Params) == 0 {
		return nil, nil
	}

	p := &policy{enabled: cfg.Enabled}

	tags, err := asStringList(cfg.Params, "strip_tags", defaultStripTags)
	if err != nil {
		return nil, err
	}
	p.stripTags = make(map[string]struct{}, len(tags))
	for _, t := range tags {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" {
			continue
		}
		p.stripTags[t] = struct{}{}
	}

	attrs, err := asStringList(cfg.Params, "strip_attributes", defaultStripAttrPatterns)
	if err != nil {
		return nil, err
	}
	p.stripAttrs = make([]string, 0, len(attrs))
	for _, a := range attrs {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == "" {
			continue
		}
		p.stripAttrs = append(p.stripAttrs, a)
	}

	cts, err := asStringList(cfg.Params, "content_types", defaultContentTypes)
	if err != nil {
		return nil, err
	}
	p.contentTypes = make([]string, 0, len(cts))
	for _, c := range cts {
		c = strings.ToLower(strings.TrimSpace(c))
		if c == "" {
			continue
		}
		p.contentTypes = append(p.contentTypes, c)
	}

	p.maxBody, err = asInt64(cfg.Params, "max_body_bytes", defaultMaxBody)
	if err != nil {
		return nil, err
	}

	return p, nil
}

// asStringList reads a []string-like value from params, falling back to
// the supplied default when the key is absent. Accepts either []string or
// []any (YAML's canonical form) containing strings.
func asStringList(params map[string]any, key string, def []string) ([]string, error) {
	raw, ok := params[key]
	if !ok {
		// Return a copy to keep callers from mutating the default.
		out := make([]string, len(def))
		copy(out, def)
		return out, nil
	}
	switch v := raw.(type) {
	case nil:
		return nil, nil
	case []string:
		out := make([]string, len(v))
		copy(out, v)
		return out, nil
	case []any:
		out := make([]string, 0, len(v))
		for i, entry := range v {
			s, ok := entry.(string)
			if !ok {
				return nil, fmt.Errorf("%s[%d]: expected string, got %T", key, i, entry)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%s: expected list of strings, got %T", key, raw)
	}
}

// asInt64 reads a numeric value (common YAML types accepted), returning
// def when the key is absent.
func asInt64(params map[string]any, key string, def int64) (int64, error) {
	raw, ok := params[key]
	if !ok {
		return def, nil
	}
	switch v := raw.(type) {
	case nil:
		return def, nil
	case int:
		return int64(v), nil
	case int32:
		return int64(v), nil
	case int64:
		return v, nil
	case uint:
		return int64(v), nil
	case uint32:
		return int64(v), nil
	case uint64:
		return int64(v), nil
	case float32:
		return int64(v), nil
	case float64:
		return int64(v), nil
	default:
		return 0, fmt.Errorf("%s: expected integer, got %T", key, raw)
	}
}

// -----------------------------------------------------------------------
// HTML rewriting.

// sanitizeHTML tokenizes body and re-emits every token except elements
// whose start tag matches pol.shouldStripTag. The skipped element's
// children are also dropped up to the matching end tag. Attributes on
// kept elements are filtered through pol.shouldStripAttr.
//
// The html.Tokenizer already treats <script> / <style> content as raw
// text until the closing tag, so a sequence like
//
//	<script><div></script>
//
// ends the script element correctly without the inner <div> re-entering
// "stripping" depth — the tokenizer reports a single TextToken followed
// by the </script> EndTagToken.
func sanitizeHTML(body []byte, pol *policy) ([]byte, error) {
	var out bytes.Buffer
	out.Grow(len(body))

	z := html.NewTokenizer(bytes.NewReader(body))

	// Depth tracking: we may encounter nested strip-tags (rare but
	// legal outside script/style, e.g. <form><form>...). Depth increments
	// only while we are skipping a subtree; it never mixes with normal
	// HTML's nesting model.
	var stripStack []string // lowercased names of currently-open strip ancestors

	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			if err := z.Err(); err != nil && err != io.EOF {
				return nil, err
			}
			break
		}

		// While skipping, we simply walk until the matching end tag of
		// the top of stripStack. We do not re-emit anything.
		if len(stripStack) > 0 {
			switch tt {
			case html.StartTagToken:
				name, _ := z.TagName()
				n := strings.ToLower(string(name))
				// Void elements (embed, input, ...) have no close tag
				// and cannot deepen the skip.
				if !isVoid(n) && n == stripStack[len(stripStack)-1] {
					stripStack = append(stripStack, n)
				}
			case html.SelfClosingTagToken:
				// Self-closing tags do not affect depth by themselves.
			case html.EndTagToken:
				name, _ := z.TagName()
				n := strings.ToLower(string(name))
				if n == stripStack[len(stripStack)-1] {
					stripStack = stripStack[:len(stripStack)-1]
				}
			}
			continue
		}

		switch tt {
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			n := strings.ToLower(string(name))
			if pol.shouldStripTag(n) {
				// Void or self-closing stripped tags: nothing to skip
				// past, emit nothing, stack unchanged. Otherwise enter
				// skip mode and wait for the matching end tag.
				if tt == html.StartTagToken && !isVoid(n) {
					stripStack = append(stripStack, n)
				}
				// Drain any attributes the tokenizer is holding so
				// internal state stays consistent.
				if hasAttr {
					for {
						_, _, more := z.TagAttr()
						if !more {
							break
						}
					}
				}
				continue
			}

			// Keep the tag; rewrite with filtered attributes.
			out.WriteByte('<')
			out.WriteString(string(name))
			if hasAttr {
				for {
					key, val, more := z.TagAttr()
					k := strings.ToLower(string(key))
					v := strings.ToLower(string(val))
					if !pol.shouldStripAttr(k, v) {
						out.WriteByte(' ')
						out.Write(key)
						out.WriteString(`="`)
						out.WriteString(html.EscapeString(string(val)))
						out.WriteByte('"')
					}
					if !more {
						break
					}
				}
			}
			if tt == html.SelfClosingTagToken {
				out.WriteString("/>")
			} else {
				out.WriteByte('>')
			}

		case html.EndTagToken:
			// Keep verbatim.
			out.Write(z.Raw())

		case html.TextToken, html.CommentToken, html.DoctypeToken:
			// Keep verbatim. Using Raw() preserves exact formatting,
			// whitespace, and any entities the upstream chose to emit.
			out.Write(z.Raw())
		}
	}

	return out.Bytes(), nil
}

// -----------------------------------------------------------------------
// Response recording.

// recorder buffers a handler's response. Writes past maxBody are counted
// but discarded so we can honour the pass-through-on-overflow policy.
type recorder struct {
	h          http.ResponseWriter // only used to satisfy interface when nil-checks happen
	header     http.Header
	buf        bytes.Buffer
	status     int
	wroteHdr   bool
	maxBody    int64
	totalBytes int64
	overflowed bool
	method     string
}

// newRecorder returns a recorder that initially borrows the upstream
// header map values. It deliberately does NOT share the upstream header
// map — we need a private clone so the handler mutations don't leak out
// until we are sure we'll forward them.
func newRecorder(w http.ResponseWriter) *recorder {
	return &recorder{
		h:      w,
		header: http.Header{},
	}
}

// setLimit sets the body-size cap after which writes are counted but
// discarded. A value <=0 disables the cap.
func (r *recorder) setLimit(n int64) {
	r.maxBody = n
}

// setMethod records the request method so HEAD responses skip the body
// write during replay.
func (r *recorder) setMethod(m string) { r.method = m }

// Header implements http.ResponseWriter.
func (r *recorder) Header() http.Header { return r.header }

// WriteHeader implements http.ResponseWriter. Repeated calls are ignored
// to mimic the real server's behavior (which logs a warning and drops
// subsequent calls).
func (r *recorder) WriteHeader(status int) {
	if r.wroteHdr {
		return
	}
	r.wroteHdr = true
	r.status = status
}

// Write implements http.ResponseWriter. Bytes past maxBody are dropped
// but still counted so the finish step can emit an accurate warning.
func (r *recorder) Write(p []byte) (int, error) {
	if !r.wroteHdr {
		r.WriteHeader(http.StatusOK)
	}
	n := len(p)
	r.totalBytes += int64(n)
	if r.maxBody > 0 {
		remaining := r.maxBody - int64(r.buf.Len())
		if remaining <= 0 {
			r.overflowed = true
			return n, nil
		}
		if int64(n) > remaining {
			r.buf.Write(p[:remaining])
			r.overflowed = true
			return n, nil
		}
	}
	r.buf.Write(p)
	return n, nil
}

// newRecorderWith is the convenience constructor used by Middleware: it
// returns a recorder already primed with the body cap and request
// method so the finish step can branch correctly.
func newRecorderWith(w http.ResponseWriter, method string, maxBody int64) *recorder {
	rec := newRecorder(w)
	rec.setLimit(maxBody)
	rec.setMethod(method)
	return rec
}

// ensure interface compliance at compile time.
var (
	_ feature.Feature     = (*Feature)(nil)
	_ http.ResponseWriter = (*recorder)(nil)
)
