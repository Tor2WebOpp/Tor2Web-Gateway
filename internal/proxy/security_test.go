package proxy

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gateway/internal/admin"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestSecurityHeaders(t *testing.T) {
	handler := securityHeadersMiddleware(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if v := rr.Header().Get("X-Frame-Options"); v != "DENY" {
		t.Errorf("X-Frame-Options: got %q, want %q", v, "DENY")
	}
	if v := rr.Header().Get("X-Content-Type-Options"); v != "nosniff" {
		t.Errorf("X-Content-Type-Options: got %q, want %q", v, "nosniff")
	}
}

// captureSlog redirects the default slog sink into a bytes.Buffer for the
// duration of the test and restores the original sink on cleanup. The
// returned buffer accumulates every JSON record emitted during the test.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	prev := slog.Default()
	buf := &bytes.Buffer{}
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

// TestRecoveryMiddleware_RedactsAdminPath verifies that when a panic
// occurs under an admin-gated path, the captured slog line contains the
// "/**/**/**" redaction rather than the raw slug+tokens. This is the
// regression guard for OPSEC leak #2.
func TestRecoveryMiddleware_RedactsAdminPath(t *testing.T) {
	const (
		slug   = "secret-slug-zzzzz"
		token1 = "tok1aaaaaaaaaaaa"
		token2 = "tok2bbbbbbbbbbbb"
	)
	gate := admin.New(admin.Config{
		Enabled: true,
		Slug:    slug,
		Token1:  token1,
		Token2:  token2,
	})

	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	})
	handler := recoveryMiddleware(gate, panicHandler)

	buf := captureSlog(t)

	req := httptest.NewRequest(http.MethodGet, "/"+slug+"/"+token1+"/"+token2+"/panel", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 after panic, got %d", rr.Code)
	}

	logged := buf.String()
	for _, secret := range []string{slug, token1, token2} {
		if strings.Contains(logged, secret) {
			t.Errorf("recovery log leaked secret %q:\n%s", secret, logged)
		}
	}
	if !strings.Contains(logged, "/**/**/**") {
		t.Errorf("expected redacted path marker in log output:\n%s", logged)
	}
}

// TestRecoveryMiddleware_PreservesNonAdminPath verifies the ordinary path
// through the recovery layer: non-admin requests must still log their raw
// URL path so operators can debug tenant traffic.
func TestRecoveryMiddleware_PreservesNonAdminPath(t *testing.T) {
	gate := admin.New(admin.Config{
		Enabled: true,
		Slug:    "zzslug",
		Token1:  "zztok1zztok1zztok1",
		Token2:  "zztok2zztok2zztok2",
	})

	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	})
	handler := recoveryMiddleware(gate, panicHandler)

	buf := captureSlog(t)
	req := httptest.NewRequest(http.MethodGet, "/tenant/alpha/page", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 after panic, got %d", rr.Code)
	}
	if !strings.Contains(buf.String(), "/tenant/alpha/page") {
		t.Errorf("expected raw non-admin path in log output:\n%s", buf.String())
	}
}

// TestRecoveryMiddleware_NoSecondWriteAfterPartialBody is the regression
// guard for P7: when the inner handler has already committed bytes to
// the client and then panics, recovery MUST NOT call http.Error — the
// second WriteHeader/Write would smuggle a fake header into the chunked
// body. The httptest.ResponseRecorder silently drops the second
// WriteHeader, so we instead assert the body never grew past what the
// inner handler wrote.
func TestRecoveryMiddleware_NoSecondWriteAfterPartialBody(t *testing.T) {
	const partial = "first-100-bytes-of-body"

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(partial))
		panic("boom after write")
	})
	handler := recoveryMiddleware(nil, inner)

	_ = captureSlog(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d (handler already wrote 200)", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	if body != partial {
		t.Errorf("body smuggling: got %q, want %q (recovery must not append a 500 page)", body, partial)
	}
	// Ensure no second 500 line has been smuggled into the body.
	if strings.Contains(body, "Internal Server Error") {
		t.Errorf("recovery wrote a smuggled 500 message into chunked body: %q", body)
	}
}

// TestRecoveryMiddleware_500WhenNoBytesWritten preserves the original
// behaviour: when the handler panics before writing anything, recovery
// still emits a clean 500.
func TestRecoveryMiddleware_500WhenNoBytesWritten(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("immediate boom")
	})
	handler := recoveryMiddleware(nil, inner)

	_ = captureSlog(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status: got %d, want 500", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Internal Server Error") {
		t.Errorf("body: got %q, want it to contain 'Internal Server Error'", rr.Body.String())
	}
}
