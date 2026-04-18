package door

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"sync"

	"gateway/internal/config"
)

// RedirectHandler decides whether a request's first path segment is a
// configured slug and, on match, picks a healthy mirror from Selector
// and writes the redirect. On non-match the handler returns false from
// Match so the outer Server can fall through to the cover handler.
//
// Every slug compare runs in constant time. We never short-circuit on
// the first byte mismatch — the total CPU cost of a request is a
// function of the number of configured slugs and their combined length,
// independent of the input path. This is the slug-equivalent of the
// admin gate's constant-time compare.
type RedirectHandler struct {
	selector *Selector

	muSlugs sync.RWMutex
	slugs   []compiledSlug
}

// compiledSlug is the pre-allocated byte form used by Match. Keeping
// the raw bytes avoids per-request allocation in the compare loop.
type compiledSlug struct {
	slug []byte
	cfg  config.SlugConf
}

// NewRedirectHandler constructs a RedirectHandler with the given slug
// set and Selector. slugs may be empty — in that case every request
// non-matches and falls through to the cover handler.
func NewRedirectHandler(slugs []config.SlugConf, sel *Selector) *RedirectHandler {
	h := &RedirectHandler{selector: sel}
	h.UpdateSlugs(slugs)
	return h
}

// UpdateSlugs hot-swaps the compiled slug set. Intended for admin
// API integration where operators add/remove slugs without restarting
// the door binary.
func (h *RedirectHandler) UpdateSlugs(slugs []config.SlugConf) {
	compiled := make([]compiledSlug, len(slugs))
	for i, s := range slugs {
		compiled[i] = compiledSlug{slug: []byte(s.Slug), cfg: s}
	}
	h.muSlugs.Lock()
	h.slugs = compiled
	h.muSlugs.Unlock()
}

// Match reports whether the first path segment of p is a configured
// slug. On match it returns the matched SlugConf and the remainder of
// the path (possibly empty). On non-match ok is false and the other
// return values are zero.
//
// The compare loop runs over every configured slug regardless of any
// early match — this preserves timing parity across "enabled but
// non-matching" and "matching" inputs. subtle.ConstantTimeCompare
// requires equal lengths, so the request segment is padded/truncated to
// the slug's length before each compare.
func (h *RedirectHandler) Match(p string) (*config.SlugConf, string, bool) {
	first, rest := splitFirstSegment(p)

	h.muSlugs.RLock()
	compiled := h.slugs
	h.muSlugs.RUnlock()

	if len(compiled) == 0 {
		return nil, "", false
	}

	var (
		matchIdx = -1
		firstB   = []byte(first)
	)
	for i := range compiled {
		padded := padTo(firstB, len(compiled[i].slug))
		eq := subtle.ConstantTimeCompare(padded, compiled[i].slug)
		// Also require that the original segment length matches the
		// slug length — otherwise an empty request would pad to all
		// zeros and accidentally match a slug of all zeros. We fold
		// the length check into the compare via ConstantTimeByteEq so
		// there is still no branch on the raw length.
		lenEq := subtle.ConstantTimeByteEq(byte(len(first)), byte(len(compiled[i].slug)))
		if eq == 1 && lenEq == 1 && matchIdx == -1 {
			// Capture the first match but keep iterating so the total
			// number of compares is a function of slug count only.
			matchIdx = i
		}
	}
	if matchIdx < 0 {
		return nil, "", false
	}
	return &compiled[matchIdx].cfg, rest, true
}

// ServeHTTP implements http.Handler. It is meant to be called by the
// outer Server only after the cover fallthrough has been decided —
// i.e. when Match already returned ok=true. Calling ServeHTTP on a
// non-matching path yields a 404 because the outer router is supposed
// to route non-matches to the cover.
func (h *RedirectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodHead:
		// Stealth: HEAD always succeeds with an empty 200 regardless
		// of path. Mimics a static page that "is there".
		writeEmpty(w, http.StatusOK)
		return
	case http.MethodGet:
		// handled below
	default:
		writeEmpty(w, http.StatusMethodNotAllowed)
		return
	}

	slug, remainder, ok := h.Match(r.URL.Path)
	if !ok {
		writeEmpty(w, http.StatusNotFound)
		return
	}
	host, live := h.selector.Pick(*slug)
	if !live {
		writeEmpty(w, http.StatusServiceUnavailable)
		return
	}

	// Build the redirect target. Preserve the trailing path + query so
	// deep links into the mirror continue to work.
	target := "https://" + host + ensureLeadingSlash(remainder)
	if q := r.URL.RawQuery; q != "" {
		target += "?" + q
	}

	hdr := w.Header()
	hdr.Set("Location", target)
	hdr.Set("Content-Length", "0")
	w.WriteHeader(slug.Status)
}

// splitFirstSegment returns the first URL path segment (without the
// leading slash) and the remainder of the path (including its leading
// slash when non-empty). Paths like "/" yield ("", "").
func splitFirstSegment(p string) (first, rest string) {
	if p == "" || p == "/" {
		return "", ""
	}
	if p[0] == '/' {
		p = p[1:]
	}
	idx := strings.IndexByte(p, '/')
	if idx < 0 {
		return p, ""
	}
	return p[:idx], p[idx:]
}

// padTo returns a slice of exactly n bytes containing src; padded with
// zero bytes if src is shorter, truncated if longer. The result is a
// fresh allocation so subsequent mutations of src do not affect it.
func padTo(src []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, src)
	return out
}

// ensureLeadingSlash returns p unchanged when it starts with "/" and
// prepends a "/" otherwise. Empty input becomes "/".
func ensureLeadingSlash(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] == '/' {
		return p
	}
	return "/" + p
}
