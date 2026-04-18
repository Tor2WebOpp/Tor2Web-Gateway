package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGenerateCSRFToken_FormatAndUniqueness(t *testing.T) {
	tok1, err := GenerateCSRFToken()
	if err != nil {
		t.Fatalf("GenerateCSRFToken: %v", err)
	}
	tok2, err := GenerateCSRFToken()
	if err != nil {
		t.Fatalf("GenerateCSRFToken (2): %v", err)
	}
	if tok1 == tok2 {
		t.Fatal("two CSRF tokens collided")
	}
	// 32 raw bytes encoded as base64url without padding is 43 chars.
	if got := len(tok1); got != 43 {
		t.Fatalf("token length = %d, want 43 (32 bytes base64url no pad)", got)
	}
	for _, c := range tok1 {
		ok := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_'
		if !ok {
			t.Fatalf("token contains non-base64url character: %q", c)
		}
	}
}

func TestValidateCSRF_GETPasses(t *testing.T) {
	s := &Session{CSRFToken: "the-token"}
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	if !ValidateCSRF(s, r) {
		t.Fatal("GET without header should pass CSRF")
	}
}

func TestValidateCSRF_HEADAndOPTIONSPass(t *testing.T) {
	s := &Session{CSRFToken: "the-token"}
	for _, m := range []string{http.MethodHead, http.MethodOptions} {
		r := httptest.NewRequest(m, "/x", nil)
		if !ValidateCSRF(s, r) {
			t.Errorf("%s without header should pass CSRF", m)
		}
	}
}

func TestValidateCSRF_POSTNoHeaderFails(t *testing.T) {
	s := &Session{CSRFToken: "the-token"}
	r := httptest.NewRequest(http.MethodPost, "/x", nil)
	if ValidateCSRF(s, r) {
		t.Fatal("POST without X-CSRF-Token must fail")
	}
}

func TestValidateCSRF_POSTMismatchedFails(t *testing.T) {
	s := &Session{CSRFToken: "the-token"}
	r := httptest.NewRequest(http.MethodPost, "/x", nil)
	r.Header.Set(CSRFHeader, "wrong-token")
	if ValidateCSRF(s, r) {
		t.Fatal("POST with mismatched token must fail")
	}
}

func TestValidateCSRF_POSTMatchingPasses(t *testing.T) {
	s := &Session{CSRFToken: "the-token"}
	r := httptest.NewRequest(http.MethodPost, "/x", nil)
	r.Header.Set(CSRFHeader, "the-token")
	if !ValidateCSRF(s, r) {
		t.Fatal("POST with matching token must pass")
	}
}

func TestValidateCSRF_NilSessionFails(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	if ValidateCSRF(nil, r) {
		t.Fatal("nil session must always fail")
	}
}

func TestValidateCSRF_NilRequestFails(t *testing.T) {
	if ValidateCSRF(&Session{CSRFToken: "x"}, nil) {
		t.Fatal("nil request must always fail")
	}
}

func TestValidateCSRF_EmptySessionTokenFails(t *testing.T) {
	s := &Session{CSRFToken: ""}
	r := httptest.NewRequest(http.MethodPost, "/x", nil)
	r.Header.Set(CSRFHeader, "anything")
	if ValidateCSRF(s, r) {
		t.Fatal("session with empty CSRFToken must reject mutating requests")
	}
}

func TestValidateCSRF_MethodCaseSensitive(t *testing.T) {
	// http.MethodPost is upper-case; lower-case "get" must NOT count
	// as safe — we want strict RFC compliance.
	s := &Session{CSRFToken: "x"}
	r := httptest.NewRequest("get", "/x", nil)
	if ValidateCSRF(s, r) {
		t.Fatal("lowercase \"get\" must not be treated as a safe method")
	}
}
