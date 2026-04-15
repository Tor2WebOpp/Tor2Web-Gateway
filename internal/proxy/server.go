package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"

	"gateway/internal/config"
	"gateway/internal/shared"
)

const (
	maxBodyBytes    = 4 * 1024 * 1024 // 4 MB
	pollInterval    = 2 * time.Second
	poolDialTimeout = 2 * time.Second
)

// Server is the assembled reverse-proxy HTTP server.
type Server struct {
	cfg        *config.Config
	httpServer *http.Server

	mu        sync.RWMutex
	poolCache []shared.BackendInfo
}

// NewServer builds the full middleware chain and returns a ready Server.
func NewServer(cfg *config.Config) (*Server, error) {
	s := &Server{cfg: cfg}

	// 1. Innermost: httputil.ReverseProxy backed by TorTransport.
	torTransport := NewTorTransport(cfg, s.getPool)

	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			// TorTransport.RoundTrip rewrites URL/Host; Director is a no-op here.
			req.Header.Del("X-Forwarded-For") // will be set by transport
		},
		Transport: torTransport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("reverse proxy error", "err", err, "path", r.URL.Path)
			serveErrorPage(w, http.StatusBadGateway)
		},
	}

	var handler http.Handler = rp

	// 2. Cache middleware (if enabled).
	if cfg.Cache.Enabled {
		c, err := NewCache(cfg.Cache.MaxSizeMB, cfg.Cache.DefaultTTL, cfg.Cache.StaticExtensions)
		if err != nil {
			return nil, fmt.Errorf("server: init cache: %w", err)
		}
		handler = c.Middleware(handler)
	}

	// 3. Rate limiter.
	rl := NewRateLimiter(&cfg.RateLimit)
	handler = rl.Middleware(handler)

	// 4. Security headers.
	handler = securityHeadersMiddleware(handler)

	// 5. Blocked paths.
	if len(cfg.Security.BlockedPaths) > 0 {
		handler = blockedPathsMiddleware(cfg.Security.BlockedPaths, handler)
	}

	// 6. Blocked methods.
	if len(cfg.Security.BlockedMethods) > 0 {
		handler = blockedMethodsMiddleware(cfg.Security.BlockedMethods, handler)
	}

	// 7. Max body size (4 MB).
	handler = maxBodyMiddleware(maxBodyBytes, handler)

	// 8. Recovery.
	handler = recoveryMiddleware(handler)

	// 9. Metrics (outermost).
	handler = metricsMiddleware(handler)

	s.httpServer = &http.Server{
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return s, nil
}

// getPool returns a snapshot of the current backend pool (safe for concurrent use).
func (s *Server) getPool() []shared.BackendInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]shared.BackendInfo, len(s.poolCache))
	copy(out, s.poolCache)
	return out
}

// ListenAndServe starts the HTTP server on addr.
func (s *Server) ListenAndServe(addr string) error {
	s.httpServer.Addr = addr
	return s.httpServer.ListenAndServe()
}

// ListenAndServeTLS obtains a certificate via ACME/CertMagic and starts an
// HTTPS server on :443. A plain HTTP listener on :80 handles ACME challenges
// and redirects all other traffic to HTTPS.
func (s *Server) ListenAndServeTLS(domain, email string) error {
	certmagic.DefaultACME.Email = email
	certmagic.DefaultACME.Agreed = true

	magic := certmagic.NewDefault()
	if err := magic.ManageSync(context.Background(), []string{domain}); err != nil {
		return fmt.Errorf("certmagic manage: %w", err)
	}

	tlsConfig := magic.TLSConfig()
	tlsConfig.NextProtos = []string{"h2", "http/1.1"}

	ln, err := tls.Listen("tcp", ":443", tlsConfig)
	if err != nil {
		return fmt.Errorf("tls listen: %w", err)
	}

	// HTTP->HTTPS redirect + ACME challenge handler on :80
	go http.ListenAndServe(":80", certmagic.DefaultACME.HTTPChallengeHandler(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			target := "https://" + r.Host + r.RequestURI
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		}),
	))

	slog.Info("gateway-proxy TLS listening", "domain", domain)
	return s.httpServer.Serve(ln)
}

// Shutdown gracefully stops the server using the provided context.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// PollPool connects to the torpool admin Unix socket and refreshes the backend
// list every pollInterval. It runs until ctx is cancelled.
func (s *Server) PollPool(ctx context.Context, socketPath string) {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: poolDialTimeout}
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/backends", nil)
			if err != nil {
				slog.Warn("pollPool: build request", "err", err)
				continue
			}
			resp, err := client.Do(req)
			if err != nil {
				slog.Warn("pollPool: request failed", "err", err)
				continue
			}

			var backends []shared.BackendInfo
			if err := json.NewDecoder(resp.Body).Decode(&backends); err != nil {
				resp.Body.Close()
				slog.Warn("pollPool: decode response", "err", err)
				continue
			}
			resp.Body.Close()

			s.mu.Lock()
			s.poolCache = backends
			s.mu.Unlock()
		}
	}
}
