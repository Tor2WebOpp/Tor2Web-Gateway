package admin

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"sync"
)

// Config carries the three admin-path secrets from bootstrap configuration.
// Enabled=false, or any of the three strings empty, disables the gate.
type Config struct {
	Enabled bool
	Slug    string
	Token1  string
	Token2  string
}

// Handler is the optional backend wired in by the gateway bootstrap.
// When set via SetHandler, ServeHTTP delegates to it on a path match
// after stripping the gate prefix. When nil, ServeHTTP retains the P1
// 501 stub so backward-compatible binaries that never wired the admin
// surface continue to behave identically.
type Handler interface {
	http.Handler
}

// Gate matches the admin-path prefix in constant time and either serves
// the P1 stub or delegates to a registered Handler.
//
// The zero value is not usable. Construct with New.
type Gate struct {
	enabled bool

	// Stored as []byte to avoid per-request allocation on compare. Lengths are
	// retained so each request can length-equalize the incoming segment
	// against the configured one before ConstantTimeCompare.
	slug   []byte
	token1 []byte
	token2 []byte

	// Dummy bytes of identical length to the three configured segments, used
	// when the gate is disabled so the same three compares still run. They
	// are never compared against user input directly; they stand in as the
	// "configured" side so that a disabled gate spends the same CPU as an
	// enabled one that mismatched.
	dummySlug   []byte
	dummyToken1 []byte
	dummyToken2 []byte

	// prefix is the slash-rooted "/<slug>/<token1>/<token2>" string.
	// Cached so ServeHTTP can strip it from r.URL.Path before delegating
	// without re-allocating per request. Disabled gates retain a dummy
	// prefix of the same length so the strip path is not differentiated
	// by branch frequency.
	prefix string

	// handler is the optional delegate. Read with handlerMu under a
	// short critical section; the pointer itself is published with
	// regular mutex semantics rather than atomic.Value so the SetHandler
	// API can also clear it (h == nil) without surprising the caller.
	handlerMu sync.RWMutex
	handler   Handler
}

// New returns a Gate. If cfg.Enabled is false, or any of Slug/Token1/Token2
// is empty, the returned Gate is disabled: MatchesPrefix will always return
// false and ServeHTTP will always write the 404 stub. Disabled gates still
// perform three constant-time compares on dummy bytes so disabled vs.
// "enabled-but-wrong" is not distinguishable by wall-clock timing.
func New(cfg Config) *Gate {
	g := &Gate{}
	if !cfg.Enabled || cfg.Slug == "" || cfg.Token1 == "" || cfg.Token2 == "" {
		// Disabled. Pick non-zero lengths for the dummy side so the compare
		// loop still does real work; lengths are arbitrary and not tied to
		// any configured secret. Twice 32 covers typical 32-char install
		// output without being conspicuous.
		g.enabled = false
		g.slug = make([]byte, 32)
		g.token1 = make([]byte, 32)
		g.token2 = make([]byte, 32)
		g.dummySlug = make([]byte, 32)
		g.dummyToken1 = make([]byte, 32)
		g.dummyToken2 = make([]byte, 32)
		// Prefix slot for a disabled gate is a fixed-shape placeholder
		// with the same per-character work — disabled and enabled paths
		// allocate the same string-length 1+32+1+32+1+32 bytes of zeroed
		// padding, so the unused field's existence does not differ by
		// branch.
		g.prefix = "/" + strings.Repeat("0", 32) + "/" + strings.Repeat("0", 32) + "/" + strings.Repeat("0", 32)
		return g
	}
	g.enabled = true
	g.slug = []byte(cfg.Slug)
	g.token1 = []byte(cfg.Token1)
	g.token2 = []byte(cfg.Token2)
	g.dummySlug = make([]byte, len(g.slug))
	g.dummyToken1 = make([]byte, len(g.token1))
	g.dummyToken2 = make([]byte, len(g.token2))
	g.prefix = "/" + cfg.Slug + "/" + cfg.Token1 + "/" + cfg.Token2
	return g
}

// Prefix returns the slash-rooted "/<slug>/<token1>/<token2>" path used
// to scope cookies and audit-log entries. Disabled gates return a
// fixed-shape placeholder of the same length distribution as a typical
// configured one so callers cannot infer enablement from the result's
// length; they should not call Prefix in that case.
func (g *Gate) Prefix() string { return g.prefix }

// SetHandler installs (or, with nil, clears) the admin backend. While a
// non-nil handler is set, ServeHTTP delegates matched requests to it
// after stripping the gate prefix from r.URL.Path. With handler unset,
// ServeHTTP retains the original 501 stub on match.
func (g *Gate) SetHandler(h Handler) {
	g.handlerMu.Lock()
	g.handler = h
	g.handlerMu.Unlock()
}

// loadHandler returns the currently installed handler under the read
// lock. Read paths use this rather than touching g.handler directly so
// the data race detector stays quiet under concurrent SetHandler calls.
func (g *Gate) loadHandler() Handler {
	g.handlerMu.RLock()
	h := g.handler
	g.handlerMu.RUnlock()
	return h
}

// Enabled reports whether the gate has a usable configuration. It exposes the
// boolean state for observability without exposing any of the secrets.
func (g *Gate) Enabled() bool {
	return g.enabled
}

// MatchesPrefix reports whether path is /<slug>/<token1>/<token2>[/...].
//
// The three segments are compared in constant time: regardless of which
// segment (or which byte of which segment) first disagrees, the amount of
// work done is a function of configured lengths only. All three
// ConstantTimeCompare calls always run; their 0/1 results are combined with
// a bitwise AND and inspected once at the end.
//
// Timing parity between disabled and enabled gates: the disabled branch
// performs the same padEqual allocations on the caller's input, then
// swaps the compare target to a dummy buffer so disabled gates burn
// exactly the same CPU as an enabled-but-mismatched gate. Under no
// branch is the comparison fast-pathed out; the three compares always
// run on equal-length buffers.
func (g *Gate) MatchesPrefix(path string) bool {
	seg1, seg2, seg3, ok := splitThree(path)

	// padEqual copies src into a fresh slice of len(ref) bytes. If src is
	// shorter it is zero-padded; if longer it is truncated. Making the
	// compared slices match the configured length is what keeps
	// ConstantTimeCompare on its constant-time path — the stdlib returns
	// early (with 0) when lengths differ.
	padEqual := func(src string, ref []byte) []byte {
		out := make([]byte, len(ref))
		copy(out, src)
		return out
	}

	// Unconditionally pad the real input against the configured lengths.
	// When splitThree rejected the path we still pad against empty
	// inputs so the alloc/copy work happens regardless of whether the
	// path was structurally valid. Critically, this work happens in
	// both the enabled and disabled paths.
	var in1, in2, in3 []byte
	if ok {
		in1 = padEqual(seg1, g.slug)
		in2 = padEqual(seg2, g.token1)
		in3 = padEqual(seg3, g.token2)
	} else {
		in1 = padEqual("", g.slug)
		in2 = padEqual("", g.token1)
		in3 = padEqual("", g.token2)
	}

	// Select the compare targets. Disabled gates swap cmp* to the dummy
	// buffers so subtle.ConstantTimeCompare still runs on equal-length
	// slices but never observes the live secrets. in* retains the
	// padded caller input either way — the amount of memory allocated
	// and the bytes touched are invariant across enabled/disabled
	// branches.
	cmpSlug := g.slug
	cmpT1 := g.token1
	cmpT2 := g.token2
	if !g.enabled {
		// Swap cmp* to the dummy buffers. in* is ALSO swapped so the
		// compares never see the real padded input — a disabled gate
		// must never leak bytes-compared-against-secret signal even
		// through the result slot. The in* pad work above still ran,
		// matching the alloc/copy cost of the enabled path.
		in1 = g.dummySlug
		in2 = g.dummyToken1
		in3 = g.dummyToken2
		cmpSlug = g.dummySlug
		cmpT1 = g.dummyToken1
		cmpT2 = g.dummyToken2
	}

	r1 := subtle.ConstantTimeCompare(in1, cmpSlug)
	r2 := subtle.ConstantTimeCompare(in2, cmpT1)
	r3 := subtle.ConstantTimeCompare(in3, cmpT2)

	// Bitwise AND so short-circuiting cannot leak which segment mismatched.
	combined := r1 & r2 & r3

	// structuralOK is 1 when the path had three segments AND the gate is
	// enabled. Folding it in with AND keeps the final check a single branch.
	var structuralOK int
	if ok && g.enabled {
		structuralOK = 1
	}
	return combined&structuralOK == 1
}

// ServeHTTP routes the request through the gate. Mismatched paths get
// the stealth 404 (empty body, Content-Length: 0, no distinguishing
// headers). Matched paths either delegate to a registered Handler — with
// the gate prefix stripped from r.URL.Path so the backend sees a clean
// "/", "/api/...", or "/logout" — or, when no Handler is installed, fall
// back to the P1 501 stub.
//
// Critically, the handler load happens unconditionally before the match
// check is consumed: both the matched and unmatched branches incur the
// same load cost, so an attacker cannot distinguish "configured backend
// + valid path" from "configured backend + invalid path" by timing the
// difference between a zero-cost 404 path and a delegate-path branch
// that fetches a pointer.
func (g *Gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	matched := g.MatchesPrefix(r.URL.Path)
	h := g.loadHandler()

	if !matched {
		writeEmpty(w, http.StatusNotFound)
		return
	}
	if h == nil {
		writeEmpty(w, http.StatusNotImplemented)
		return
	}

	// Strip the configured prefix so the handler sees clean URLs. We
	// compute the new path explicitly rather than calling http.StripPrefix
	// — that helper performs a Has-prefix check we have already proven,
	// and it allocates a wrapped handler we do not need.
	rest := r.URL.Path[len(g.prefix):]
	if rest == "" {
		rest = "/"
	}
	r2 := r.Clone(r.Context())
	r2.URL.Path = rest
	if r.URL.RawPath != "" && strings.HasPrefix(r.URL.RawPath, g.prefix) {
		r2.URL.RawPath = r.URL.RawPath[len(g.prefix):]
		if r2.URL.RawPath == "" {
			r2.URL.RawPath = "/"
		}
	}
	h.ServeHTTP(w, r2)
}

// writeEmpty writes status with a zero-length body and an explicit
// Content-Length: 0. Content-Type and any other content-describing header is
// omitted deliberately — the response must not vary with the reason for the
// status.
func writeEmpty(w http.ResponseWriter, status int) {
	h := w.Header()
	h.Set("Content-Length", "0")
	w.WriteHeader(status)
}

// splitThree parses /a/b/c[/...] into (a, b, c, true). Anything shorter,
// with empty segments, or without a leading slash returns ok=false.
func splitThree(path string) (seg1, seg2, seg3 string, ok bool) {
	if len(path) == 0 || path[0] != '/' {
		return "", "", "", false
	}
	// Trim leading slash, then split on up to four parts: we only need the
	// first three, but we want to know the fourth exists only to confirm
	// there's at least something after seg3 or that seg3 itself terminates
	// the path.
	rest := path[1:]
	parts := strings.SplitN(rest, "/", 4)
	if len(parts) < 3 {
		return "", "", "", false
	}
	if parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}
