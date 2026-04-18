package proxy

import (
	"testing"

	"gateway/internal/admin"
)

// TestRedactPath_NilGate verifies that callers who have not yet wired a gate
// (legacy single-tenant boot path) see the raw URL path in logs. This is
// the documented legacy behaviour.
func TestRedactPath_NilGate(t *testing.T) {
	const path = "/foo/bar/baz/qux"
	if got := redactPath(nil, path); got != path {
		t.Errorf("nil gate: got %q, want %q", got, path)
	}
}

// TestRedactPath_DisabledGate verifies that a gate with missing secrets
// (Enabled=false or any segment empty) passes through the raw path. A
// disabled gate has no secret to redact, so redaction would only obscure
// debugging output for no security gain.
func TestRedactPath_DisabledGate(t *testing.T) {
	cases := []admin.Config{
		{}, // Enabled=false
		{Enabled: true, Slug: "ops", Token1: "t1"}, // Token2 empty
		{Enabled: false, Slug: "ops", Token1: "t1", Token2: "t2"},
	}
	const path = "/ops/t1/t2/admin"
	for i, cfg := range cases {
		g := admin.New(cfg)
		if got := redactPath(g, path); got != path {
			t.Errorf("case %d disabled gate: got %q, want %q", i, got, path)
		}
	}
}

// TestRedactPath_EnabledMatching verifies that when the gate is fully
// enabled AND the path matches the configured slug+tokens, the first three
// segments are replaced with "/**/**/**" and any trailing subpath is
// preserved so log readers can still see what was hit under the gate.
func TestRedactPath_EnabledMatching(t *testing.T) {
	g := admin.New(admin.Config{
		Enabled: true,
		Slug:    "supersecretops",
		Token1:  "aaaaaaaaaaaaaaaa",
		Token2:  "bbbbbbbbbbbbbbbb",
	})

	tests := []struct {
		in   string
		want string
	}{
		{"/supersecretops/aaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbb", "/**/**/**"},
		{"/supersecretops/aaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbb/", "/**/**/**"},
		{"/supersecretops/aaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbb/panel", "/**/**/**/panel"},
		{"/supersecretops/aaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbb/nodes/42", "/**/**/**/nodes/42"},
	}
	for _, tt := range tests {
		got := redactPath(g, tt.in)
		if got != tt.want {
			t.Errorf("redactPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestRedactPath_EnabledNonMatching verifies that non-admin paths are
// returned untouched even when the gate is enabled — ordinary tenant
// traffic must remain fully observable in logs.
func TestRedactPath_EnabledNonMatching(t *testing.T) {
	g := admin.New(admin.Config{
		Enabled: true,
		Slug:    "supersecretops",
		Token1:  "aaaaaaaaaaaaaaaa",
		Token2:  "bbbbbbbbbbbbbbbb",
	})

	cases := []string{
		"/",
		"/login",
		"/api/v1/status",
		"/supersecretops", // single segment, not enough to match
		"/supersecretops/aaaaaaaaaaaaaaaa",                    // two segments
		"/supersecretops/aaaaaaaaaaaaaaaa/WRONG",              // wrong token2
		"/WRONG/aaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbb",            // wrong slug
		"/supersecretops/WRONG/bbbbbbbbbbbbbbbb",              // wrong token1
		"/prefix/supersecretops/aaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbb", // slug not first segment
	}
	for _, in := range cases {
		if got := redactPath(g, in); got != in {
			t.Errorf("non-matching path %q: got %q, want unchanged", in, got)
		}
	}
}

// TestRedactPath_DoesNotLeakSecrets is a regression smoke test: given the
// configured slug and tokens, the redacted output must not contain any of
// them as substrings. This is the property log-based OPSEC relies on.
func TestRedactPath_DoesNotLeakSecrets(t *testing.T) {
	const (
		slug   = "zeta-admin-sluggg"
		token1 = "tok1xxxxxxxxxxxx"
		token2 = "tok2yyyyyyyyyyyy"
	)
	g := admin.New(admin.Config{
		Enabled: true,
		Slug:    slug,
		Token1:  token1,
		Token2:  token2,
	})

	in := "/" + slug + "/" + token1 + "/" + token2 + "/backends"
	got := redactPath(g, in)
	for _, secret := range []string{slug, token1, token2} {
		if contains(got, secret) {
			t.Errorf("redacted path %q leaks secret substring %q", got, secret)
		}
	}
}

// contains is a tiny stdlib-free substring helper so this test does not
// pull strings in just for a test-only assertion.
func contains(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	if len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
