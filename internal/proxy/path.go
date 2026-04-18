package proxy

import (
	"strings"

	"gateway/internal/admin"
)

// redactPath returns path with any admin-prefixed segments elided. When g is
// non-nil and enabled, if the path matches the gate's prefix, the first three
// segments (slug + two tokens) are replaced with "/**/**/**". Otherwise the
// path is returned unchanged. When g is nil the full path is always returned
// (legacy code paths before the gate was wired).
//
// The redaction is a defence-in-depth measure: once a path has reached the
// inner middleware it has already passed the gate's constant-time check, so
// any panic/error/CF-header log at that layer would otherwise leak the
// configured slug+tokens verbatim.
func redactPath(g *admin.Gate, path string) string {
	if g == nil {
		return path
	}
	if !g.MatchesPrefix(path) {
		return path
	}
	// MatchesPrefix only returns true when the gate is enabled AND the path
	// has at least three non-empty segments, so the slice operations below
	// are always safe.
	if len(path) == 0 || path[0] != '/' {
		return path
	}
	rest := path[1:]
	parts := strings.SplitN(rest, "/", 4)
	if len(parts) < 3 {
		return path
	}
	redacted := "/**/**/**"
	if len(parts) == 4 && parts[3] != "" {
		redacted += "/" + parts[3]
	}
	return redacted
}
