package admin

import (
	"crypto/subtle"
	"net/http"
)

// CSRFHeader is the HTTP header carrying the CSRF token from the
// client. The same name is used in both directions: the server emits
// it on safe-method responses for the UI to cache, and the UI echoes
// it on mutating requests.
const CSRFHeader = "X-CSRF-Token"

// GenerateCSRFToken returns a fresh 256-bit random token encoded as
// base64url without padding. It is safe to use for HTTP headers and
// URL query strings.
func GenerateCSRFToken() (string, error) {
	return randomToken(csrfBytes)
}

// ValidateCSRF reports whether the supplied request is permitted with
// respect to CSRF protection. Safe methods (GET, HEAD, OPTIONS) are
// always permitted; mutating methods are permitted only when the
// X-CSRF-Token header matches the session's stored token under a
// constant-time compare.
//
// A nil session always fails — even on safe methods — because the
// session is also where the CSRF token lives, and the caller should
// have rejected the request before reaching CSRF validation.
func ValidateCSRF(session *Session, r *http.Request) bool {
	if session == nil || r == nil {
		return false
	}
	if isSafeMethod(r.Method) {
		return true
	}
	provided := r.Header.Get(CSRFHeader)
	if provided == "" {
		return false
	}
	expected := session.CSRFToken
	if expected == "" {
		// A session with no CSRF token cannot authorize mutations.
		// This should not occur — Create always populates CSRFToken
		// — but the explicit guard prevents a degenerate session
		// from accepting empty headers under constant-time compare.
		return false
	}
	// Equal-length compare. We pad both sides to a fixed buffer so a
	// length mismatch does not short-circuit out of ConstantTimeCompare
	// (the stdlib returns 0 immediately when lengths differ, which is
	// the safe behaviour but leaks a single bit about the token's
	// length).
	const sz = 64
	a := make([]byte, sz)
	b := make([]byte, sz)
	copy(a, provided)
	copy(b, expected)
	return subtle.ConstantTimeCompare(a, b) == 1
}

// isSafeMethod returns true for methods that do not mutate server
// state per RFC 7231 sec 4.2.1.
func isSafeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}
