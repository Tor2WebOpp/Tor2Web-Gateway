package door

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/caddyserver/certmagic"

	"gateway/internal/admin"
	"gateway/internal/config"
	"gateway/internal/metrics"
)

// Server is the assembled door HTTP server. It owns the cover handler,
// the redirect handler, and the admin gate, and exposes
// ListenAndServeTLS / Shutdown for cmd/gateway-door to drive.
//
// Door servers never hold Tor state, never consult the feature
// registry, and never emit logs that name the mirror chosen at INFO
// level. The selector, labeler, and gate are all injected so tests can
// swap them without touching package-level state.
type Server struct {
	cover    *CoverHandler
	redirect *RedirectHandler
	gate     *admin.Gate
	labeler  *metrics.Labeler

	httpServer *http.Server
}

// NewServer builds a ready-to-serve door from cfg. sel is the shared
// mirror-health table the redirect handler consults; gate is the
// admin carve-out; labeler is the OPSEC-safe metric-label producer.
// Either gate or labeler may be nil — a disabled gate and a raw-label
// labeler are substituted so the door keeps booting.
func NewServer(cfg *config.Config, sel *Selector, gate *admin.Gate, labeler *metrics.Labeler) (*Server, error) {
	if cfg == nil {
		return nil, errors.New("door: cfg is required")
	}
	if sel == nil {
		return nil, errors.New("door: selector is required")
	}
	cover, err := NewCoverHandler(cfg.Door.Cover)
	if err != nil {
		return nil, fmt.Errorf("door: cover handler: %w", err)
	}
	redirect := NewRedirectHandler(cfg.Door.Slugs, sel)

	if gate == nil {
		gate = admin.New(admin.Config{})
	}

	s := &Server{
		cover:    cover,
		redirect: redirect,
		gate:     gate,
		labeler:  labeler,
	}
	s.httpServer = &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 * 1024,
	}
	return s, nil
}

// ServeHTTP implements http.Handler. The routing table is intentionally
// tiny:
//
//	admin gate prefix          → gate.ServeHTTP (501 on match, 404 else)
//	HEAD any                   → 200 empty body
//	GET  /                     → cover
//	GET  /<slug>[/...]         → redirect
//	GET  other                 → cover (so operators can add deep links
//	                              to the static page without rewriting)
//	POST/PUT/DELETE/PATCH/...  → 405 empty body
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Admin gate first — must run on every request so gate paths are
	// never logged or metered by the door.
	if s.gate.MatchesPrefix(r.URL.Path) {
		s.gate.ServeHTTP(w, r)
		return
	}

	// HEAD always succeeds with an empty 200. The gate ran first so
	// HEADs on the admin path stay gated.
	if r.Method == http.MethodHead {
		writeEmpty(w, http.StatusOK)
		return
	}

	switch r.Method {
	case http.MethodGet:
		// continue
	default:
		writeEmpty(w, http.StatusMethodNotAllowed)
		return
	}

	// Slug match delegates to redirect; on non-match fall through to
	// the cover handler.
	if _, _, ok := s.redirect.Match(r.URL.Path); ok {
		s.redirect.ServeHTTP(w, r)
		return
	}
	s.cover.ServeHTTP(w, r)
}

// UpdateSlugs hot-reloads the slug set without restarting the binary.
// Intended for admin-API integration.
func (s *Server) UpdateSlugs(slugs []config.SlugConf) {
	s.redirect.UpdateSlugs(slugs)
}

// Redirect returns the redirect handler so cmd-level tests can inspect
// or hot-update the slug set without reaching through ServeHTTP.
func (s *Server) Redirect() *RedirectHandler { return s.redirect }

// Cover returns the cover handler; same rationale as Redirect().
func (s *Server) Cover() *CoverHandler { return s.cover }

// HTTPServer returns the underlying *http.Server so callers (tests,
// cmd wiring) can install a custom listener.
func (s *Server) HTTPServer() *http.Server { return s.httpServer }

// ListenAndServe binds addr and serves plain HTTP. Intended for tests
// and legacy installs; production doors always go through
// ListenAndServeTLS.
func (s *Server) ListenAndServe(addr string) error {
	s.httpServer.Addr = addr
	return s.httpServer.ListenAndServe()
}

// ListenAndServeTLS obtains a certificate via ACME/CertMagic and serves
// :443 with a plain HTTP redirect on :80. Mirrors proxy.Server's
// behaviour so operators can reuse the same DNS + certmagic cache.
func (s *Server) ListenAndServeTLS(domain, email string) error {
	certmagic.DefaultACME.Email = email
	certmagic.DefaultACME.Agreed = true

	magic := certmagic.NewDefault()
	if err := magic.ManageSync(context.Background(), []string{domain}); err != nil {
		return fmt.Errorf("door: certmagic manage: %w", err)
	}
	tlsConfig := magic.TLSConfig()
	tlsConfig.NextProtos = []string{"h2", "http/1.1"}

	s.httpServer.Addr = ":443"
	s.httpServer.TLSConfig = tlsConfig
	return s.httpServer.ListenAndServeTLS("", "")
}

// Shutdown gracefully stops the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer == nil {
		return nil
	}
	return s.httpServer.Shutdown(ctx)
}
