package admin

import (
	"errors"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"time"

	"gateway/internal/metrics"
)

// HandlerConfig wires the runtime collaborators into the admin Handler.
//
// The handler owns the session/lockout/CSRF chain and dispatches to a
// node-type-specific APIRouter for /api/* requests. UI is the embedded
// asset filesystem; pass nil for "no UI" — admin paths still work, GET /
// just returns 204.
//
// PathPrefix is the slash-rooted "/<slug>/<token1>/<token2>" prefix the
// Gate strips before delegating. The Handler uses it to scope the
// session cookie's Path attribute and to render the post-issuance
// 302 redirect.
type HandlerConfig struct {
	NodeID     string
	NodeType   string
	PathPrefix string
	Sessions   *SessionStore
	Lockout    *Lockout
	Audit      *Log
	Labeler    *metrics.Labeler
	UI         fs.FS
	APIRouter  http.Handler
}

// NewHandler constructs the admin Handler. The returned http.Handler is
// safe to install via Gate.SetHandler; it expects the Gate to have
// already stripped the configured PathPrefix from r.URL.Path.
//
// All collaborators except APIRouter and UI are required. Passing nil
// for any of Sessions/Lockout/Audit/Labeler yields an error rather than
// panicking on the first request — operators see the misconfiguration
// at boot.
func NewHandler(cfg HandlerConfig) (http.Handler, error) {
	if cfg.Sessions == nil {
		return nil, errors.New("admin: HandlerConfig.Sessions is required")
	}
	if cfg.Lockout == nil {
		return nil, errors.New("admin: HandlerConfig.Lockout is required")
	}
	if cfg.Audit == nil {
		return nil, errors.New("admin: HandlerConfig.Audit is required")
	}
	if cfg.Labeler == nil {
		return nil, errors.New("admin: HandlerConfig.Labeler is required")
	}
	return &handler{cfg: cfg}, nil
}

// handler is the unexported implementation; the only constructor is
// NewHandler so callers cannot bypass the wiring checks.
type handler struct {
	cfg HandlerConfig
}

// ServeHTTP implements the admin request lifecycle:
//   - lockout check on the source IP hash → 404 on backoff/banned
//   - session resolution: cookie → existing session, otherwise issue a
//     fresh session (the URL itself is the credential)
//   - first-issue redirect to PathPrefix+"/" so the URL secrets do not
//     linger in the address bar after the initial load
//   - CSRF check on mutating methods, audited on rejection
//   - dispatch: /api/* → APIRouter, /static/* → UI, "/" → UI index,
//     /logout → builtin (the API router also exposes /api/logout)
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ipHash := h.ipHash(r)

	// 1. Lockout: silently 404 so a mistyped URL does not look any
	// different from a missing route on a fresh node.
	if h.cfg.Lockout.Check(ipHash) != StateAllowed {
		writeEmpty(w, http.StatusNotFound)
		return
	}

	// 2. Session resolution. Existing cookie → refresh and continue.
	// Missing/expired → issue a fresh session and 302 to PathPrefix+"/".
	sid := SessionIDFromRequest(r)
	var (
		sess   *Session
		issued bool
	)
	if sid != "" {
		if existing, ok := h.cfg.Sessions.Get(sid); ok {
			h.cfg.Sessions.Refresh(sid)
			sess = existing
		}
	}
	if sess == nil {
		s, err := h.cfg.Sessions.Create(ipHash)
		if err != nil {
			// Failure to mint is operational — do not leak details.
			writeEmpty(w, http.StatusInternalServerError)
			return
		}
		sess = s
		issued = true
		// Lockout reset is the canonical "successful entry" hook.
		h.cfg.Lockout.RecordSuccess(ipHash)
		SetSessionCookie(w, h.cfg.PathPrefix, sess, h.cfg.Sessions.idleTTL)
	}

	// Echo the CSRF token on every response so the UI can cache it.
	w.Header().Set(CSRFHeader, sess.CSRFToken)

	// 3. First-load redirect: send the operator to a clean URL once.
	if issued {
		http.Redirect(w, r, h.cfg.PathPrefix+"/", http.StatusFound)
		return
	}

	// 4. CSRF check on mutating methods. Rejection is audited and the
	// caller sees a fixed 403 with no body — same shape regardless of
	// whether the missing header or the wrong value was at fault.
	if !ValidateCSRF(sess, r) {
		writeEmpty(w, http.StatusForbidden)
		_ = h.cfg.Audit.Write(Event{
			Time:      time.Now(),
			Actor:     sess.ID,
			ActorIP:   ipHash,
			NodeID:    h.cfg.NodeID,
			Action:    "csrf.reject",
			Target:    r.URL.Path,
			SessionID: sess.ID,
		})
		return
	}

	// 5. Dispatch.
	path := r.URL.Path
	switch {
	case path == "/logout":
		h.serveLogout(w, r, sess, ipHash)
		return
	case strings.HasPrefix(path, "/api/"):
		if h.cfg.APIRouter != nil {
			h.cfg.APIRouter.ServeHTTP(w, r)
			return
		}
		writeEmpty(w, http.StatusNotFound)
		return
	case strings.HasPrefix(path, "/static/"):
		// The embed root is the admin package dir; assets live under
		// ui/static/. Map /static/foo → ui/static/foo before the FS read.
		h.serveUI(w, r, "ui/"+strings.TrimPrefix(path, "/"))
		return
	case path == "/" || path == "":
		h.serveUI(w, r, "ui/index.html")
		return
	}
	writeEmpty(w, http.StatusNotFound)
}

// serveLogout invalidates the session record and clears the cookie. The
// API router also exposes /api/logout for clients that prefer the JSON
// surface; both paths share the same Delete + ClearSessionCookie shape.
func (h *handler) serveLogout(w http.ResponseWriter, r *http.Request, sess *Session, ipHash string) {
	h.cfg.Sessions.Delete(sess.ID)
	ClearSessionCookie(w, h.cfg.PathPrefix)
	_ = h.cfg.Audit.Write(Event{
		Time:      time.Now(),
		Actor:     sess.ID,
		ActorIP:   ipHash,
		NodeID:    h.cfg.NodeID,
		Action:    "session.logout",
		SessionID: sess.ID,
	})
	w.WriteHeader(http.StatusNoContent)
}

// serveUI serves a file from the embedded UI filesystem. Missing files
// return 404 with the same empty-body shape as the rest of the gate.
func (h *handler) serveUI(w http.ResponseWriter, r *http.Request, name string) {
	if h.cfg.UI == nil {
		writeEmpty(w, http.StatusNoContent)
		return
	}
	data, err := fs.ReadFile(h.cfg.UI, name)
	if err != nil {
		writeEmpty(w, http.StatusNotFound)
		return
	}
	switch {
	case strings.HasSuffix(name, ".html"):
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case strings.HasSuffix(name, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case strings.HasSuffix(name, ".js"):
		w.Header().Set("Content-Type", "application/javascript")
	case strings.HasSuffix(name, ".json"):
		w.Header().Set("Content-Type", "application/json")
	case strings.HasSuffix(name, ".svg"):
		w.Header().Set("Content-Type", "image/svg+xml")
	}
	_, _ = w.Write(data)
}

// ipHash returns the hashed client IP for use as the lockout/audit key.
// The labeler is required at construction time so this is always safe.
func (h *handler) ipHash(r *http.Request) string {
	host := r.RemoteAddr
	if hh, _, err := net.SplitHostPort(host); err == nil {
		host = hh
	}
	return h.cfg.Labeler.ClientIP(host)
}
