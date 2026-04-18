package admin

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gateway/internal/metrics"
)

// handlerHarness wires the minimum collaborators NewHandler needs and
// returns the constructed http.Handler plus the SessionStore and
// Lockout so tests can poke at runtime state directly.
type handlerHarness struct {
	h        http.Handler
	sessions *SessionStore
	lockout  *Lockout
	audit    *Log
	labeler  *metrics.Labeler
	prefix   string
}

func newHandlerHarness(t *testing.T, api http.Handler) *handlerHarness {
	t.Helper()
	tmp := t.TempDir()

	audit, err := OpenLog(tmp)
	if err != nil {
		t.Fatalf("OpenLog: %v", err)
	}
	t.Cleanup(func() { _ = audit.Close() })

	lab, err := metrics.NewLabeler(metrics.Config{
		HashTenantLabels: true,
		SaltFile:         filepath.Join(tmp, "salt"),
	})
	if err != nil {
		t.Fatalf("NewLabeler: %v", err)
	}

	cfg := HandlerConfig{
		NodeID:     "test-node",
		NodeType:   "hub",
		PathPrefix: "/admin",
		Sessions:   NewSessionStore(15*time.Minute, 8*time.Hour),
		Lockout: NewLockout(LockoutConfig{
			SoftThreshold: 3, SoftWindow: 60 * time.Second, SoftBackoff: 30 * time.Second,
			HardThreshold: 10, HardWindow: 10 * time.Minute, HardBan: time.Hour,
		}),
		Audit:     audit,
		Labeler:   lab,
		UI:        UIFS, // serveUI looks for "ui/index.html" — pass the root FS, not a sub-FS.
		APIRouter: api,
	}
	h, err := NewHandler(cfg)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return &handlerHarness{
		h:        h,
		sessions: cfg.Sessions,
		lockout:  cfg.Lockout,
		audit:    audit,
		labeler:  lab,
		prefix:   cfg.PathPrefix,
	}
}

// TestHandler_FreshEntryIssuesCookieAndRedirects: a request with no
// cookie gets a brand-new gw_adm cookie plus a 302 to prefix + "/".
func TestHandler_FreshEntryIssuesCookieAndRedirects(t *testing.T) {
	hr := newHandlerHarness(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.1:55555"
	rec := httptest.NewRecorder()
	hr.h.ServeHTTP(rec, req)
	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("want 302, got %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/admin/" {
		t.Fatalf("Location = %q, want /admin/", loc)
	}
	var found bool
	for _, c := range resp.Cookies() {
		if c.Name == CookieName {
			found = true
			if c.Path != "/admin" {
				t.Errorf("cookie Path = %q, want /admin", c.Path)
			}
			if !c.HttpOnly {
				t.Error("cookie should be HttpOnly")
			}
		}
	}
	if !found {
		t.Fatalf("missing %s cookie", CookieName)
	}
}

// TestHandler_ValidCookieServesUI: a valid session cookie skips the
// redirect and serves the UI index at "/".
func TestHandler_ValidCookieServesUI(t *testing.T) {
	hr := newHandlerHarness(t, nil)
	sess, err := hr.sessions.Create("ip-hash")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.1:55555"
	req.AddCookie(&http.Cookie{Name: CookieName, Value: sess.ID})

	rec := httptest.NewRecorder()
	hr.h.ServeHTTP(rec, req)
	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Admin ready") {
		t.Fatalf("body did not contain UI marker: %q", body)
	}
}

// TestHandler_StaleCookieReissues: an unknown cookie value triggers
// fresh-entry path (mint + 302).
func TestHandler_StaleCookieReissues(t *testing.T) {
	hr := newHandlerHarness(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.2:1234"
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "stale-id-not-in-store"})

	rec := httptest.NewRecorder()
	hr.h.ServeHTTP(rec, req)
	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("want 302 on stale cookie, got %d", resp.StatusCode)
	}
}

// TestHandler_LogoutClearsCookie: POST /logout deletes the session and
// emits a Max-Age=-1 cookie.
func TestHandler_LogoutClearsCookie(t *testing.T) {
	hr := newHandlerHarness(t, nil)
	sess, _ := hr.sessions.Create("ip-hash")

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.RemoteAddr = "203.0.113.1:55555"
	req.AddCookie(&http.Cookie{Name: CookieName, Value: sess.ID})
	req.Header.Set(CSRFHeader, sess.CSRFToken)

	rec := httptest.NewRecorder()
	hr.h.ServeHTTP(rec, req)
	resp := rec.Result()
	defer resp.Body.Close()

	if _, ok := hr.sessions.Get(sess.ID); ok {
		t.Fatal("session still present after logout")
	}
	for _, c := range resp.Cookies() {
		if c.Name == CookieName && c.MaxAge >= 0 {
			t.Fatalf("logout cookie MaxAge = %d, want < 0", c.MaxAge)
		}
	}
}

// TestHandler_ApiMeReturnsSessionInfo: /api/me returns JSON with the
// node id plus session metadata. The handler delegates to the API
// router for /api/* — we wire NewRouter() so the route is live.
func TestHandler_ApiMeReturnsSessionInfo(t *testing.T) {
	api := NewRouter(Routes{NodeID: "test-node", NodeType: "hub"})
	hr := newHandlerHarness(t, api)
	sess, _ := hr.sessions.Create("ip-hash")
	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	req.RemoteAddr = "203.0.113.1:55555"
	req.AddCookie(&http.Cookie{Name: CookieName, Value: sess.ID})

	rec := httptest.NewRecorder()
	hr.h.ServeHTTP(rec, req)
	resp := rec.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "test-node") {
		t.Fatalf("body missing node id: %q", body)
	}
}

// TestHandler_ApiMutateRequiresCSRF: POST /api/poke without
// X-CSRF-Token is 403; with a matching token it reaches the API mux.
func TestHandler_ApiMutateRequiresCSRF(t *testing.T) {
	api := http.NewServeMux()
	called := false
	api.HandleFunc("/api/poke", func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	hr := newHandlerHarness(t, api)
	sess, _ := hr.sessions.Create("ip-hash")

	req := httptest.NewRequest(http.MethodPost, "/api/poke", nil)
	req.RemoteAddr = "203.0.113.1:55555"
	req.AddCookie(&http.Cookie{Name: CookieName, Value: sess.ID})
	rec := httptest.NewRecorder()
	hr.h.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 without CSRF, got %d", rec.Code)
	}
	if called {
		t.Fatal("API handler invoked despite CSRF reject")
	}

	req2 := httptest.NewRequest(http.MethodPost, "/api/poke", nil)
	req2.RemoteAddr = "203.0.113.1:55555"
	req2.AddCookie(&http.Cookie{Name: CookieName, Value: sess.ID})
	req2.Header.Set(CSRFHeader, sess.CSRFToken)
	rec2 := httptest.NewRecorder()
	hr.h.ServeHTTP(rec2, req2)
	if rec2.Result().StatusCode != http.StatusOK {
		t.Fatalf("want 200 with valid CSRF, got %d", rec2.Code)
	}
	if !called {
		t.Fatal("API handler not invoked with valid CSRF")
	}
}

// TestHandler_HardBanned404: a hard-banned source IP gets the stealth
// 404 even when the session cookie is otherwise valid. The lockout
// check must run before session resolution.
func TestHandler_HardBanned404(t *testing.T) {
	hr := newHandlerHarness(t, nil)

	// Trip the hard threshold for the IP we'll use. The handler hashes
	// remoteAddr through the labeler so we mirror the same path here
	// to record failures against the matching key.
	target := hr.labeler.ClientIP("198.51.100.42")
	for i := 0; i < 20; i++ {
		hr.lockout.RecordFailure(target)
	}

	sess, _ := hr.sessions.Create(target)
	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	req.RemoteAddr = "198.51.100.42:9999"
	req.AddCookie(&http.Cookie{Name: CookieName, Value: sess.ID})

	rec := httptest.NewRecorder()
	hr.h.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusNotFound {
		t.Fatalf("want 404 for hard-banned IP, got %d", rec.Code)
	}
}

// TestHandler_StaticFromUI: missing files return 404 from the FS
// handler chain. The P3 UI stub ships only index.html.
func TestHandler_StaticFromUI(t *testing.T) {
	hr := newHandlerHarness(t, nil)
	sess, _ := hr.sessions.Create("ip-hash")
	req := httptest.NewRequest(http.MethodGet, "/static/missing.css", nil)
	req.RemoteAddr = "203.0.113.1:55555"
	req.AddCookie(&http.Cookie{Name: CookieName, Value: sess.ID})

	rec := httptest.NewRecorder()
	hr.h.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusNotFound {
		t.Fatalf("want 404 for missing static file, got %d", rec.Code)
	}
}

// TestHandler_NoServerHeader confirms Server is never advertised.
func TestHandler_NoServerHeader(t *testing.T) {
	hr := newHandlerHarness(t, nil)
	sess, _ := hr.sessions.Create("ip-hash")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.1:55555"
	req.AddCookie(&http.Cookie{Name: CookieName, Value: sess.ID})

	rec := httptest.NewRecorder()
	hr.h.ServeHTTP(rec, req)
	resp := rec.Result()
	defer resp.Body.Close()
	if got := resp.Header.Get("Server"); got != "" {
		t.Fatalf("Server header leaked: %q", got)
	}
}

// TestHandler_RejectsMissingCollaborators: NewHandler must return an
// error rather than panicking on a missing dependency.
func TestHandler_RejectsMissingCollaborators(t *testing.T) {
	if _, err := NewHandler(HandlerConfig{}); err == nil {
		t.Fatal("expected error from empty HandlerConfig")
	}
}
