package proxy

import "testing"

// TestNormalizeMethod_KnownPassthrough confirms every standard HTTP
// method maps to itself. Required so existing dashboards that filter on
// e.g. method="GET" keep working.
func TestNormalizeMethod_KnownPassthrough(t *testing.T) {
	for _, m := range []string{
		"GET", "POST", "PUT", "PATCH", "DELETE",
		"HEAD", "OPTIONS", "CONNECT", "TRACE",
	} {
		if got := normalizeMethod(m); got != m {
			t.Errorf("known method %q: got %q, want %q", m, got, m)
		}
	}
}

// TestNormalizeMethod_UnknownBucketsToOTHER is the regression guard for
// P11: an attacker rotating the request method up to MaxHeaderBytes
// must not blow up Prometheus label cardinality. Anything outside the
// closed allowlist must collapse to a single "OTHER" bucket.
func TestNormalizeMethod_UnknownBucketsToOTHER(t *testing.T) {
	cases := []string{
		"FOO-BAR",
		"PROPFIND",
		"",
		"get",         // case-sensitive; lowercase is not a known method
		"Get",         // mixed-case
		"GETGETGETGET",
		"\x00\x01\x02",
		"A_REALLY_LONG_ATTACKER_CONTROLLED_METHOD_NAME_THAT_BLOATS_LABELS",
	}
	for _, m := range cases {
		if got := normalizeMethod(m); got != "OTHER" {
			t.Errorf("unknown method %q: got %q, want %q", m, got, "OTHER")
		}
	}
}
