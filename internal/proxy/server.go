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

	"gateway/internal/admin"
	"gateway/internal/config"
	"gateway/internal/feature"
	"gateway/internal/feature/abuse"
	"gateway/internal/feature/blocklist"
	featgeoip "gateway/internal/feature/geoip"
	featheaders "gateway/internal/feature/headers"
	featnegcache "gateway/internal/feature/negcache"
	featratelimit "gateway/internal/feature/ratelimit"
	featsanitize "gateway/internal/feature/sanitize"
	featstaticcache "gateway/internal/feature/staticcache"
	featttlblock "gateway/internal/feature/ttlblock"
	"gateway/internal/metrics"
	"gateway/internal/shared"
	"gateway/internal/transport"
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

	// redirectServer is the :80 ACME-challenge / HTTPS-redirect listener
	// created by ListenAndServeTLS. It is kept here so Shutdown can stop
	// it gracefully alongside the main TLS server. Nil when ListenAndServe
	// (no TLS) is in use.
	redirectServer *http.Server

	// transport is the edge<->hub transport used for SOCKS5 and admin
	// API dialling. Set by NewServer and never mutated afterward.
	transport transport.Transport

	// registry owns the feature middleware chain + hot-reload plumbing.
	registry *feature.Registry

	// adminGate serves the path-gated admin carve-out (501 in P1).
	adminGate *admin.Gate

	// labeler produces OPSEC-safe metric labels (hashed tenant host,
	// hashed client IP). Nil is tolerated for pre-P1 callers.
	labeler *metrics.Labeler

	// featureHandles keeps references to the registered features so the
	// server can call lifecycle hooks (Start/Stop on rate-limit sweepers,
	// Observe on features that take additional tenant maps).
	featureHandles featureHandles

	// snapshotClient feeds tenant+globals configuration into the
	// registry. Nil in tests that drive reg.Reload directly.
	snapshotClient SnapshotClient

	// negCache is the per-tenant dead-backend blacklist wired into
	// TorTransport. Exposed so tests can seed it deterministically.
	negCache *featnegcache.Cache

	// torTransport is the inner RoundTripper that owns per-port
	// *http.Transport caches + breakers. Retained so Shutdown can drain
	// its idle-conn pools; the outer transport.Transport handles overlay
	// teardown separately.
	torTransport *TorTransport

	mu        sync.RWMutex
	poolCache []shared.BackendInfo
}

// featureHandles is the set of pointer references kept by Server so it
// can drive non-registry lifecycle hooks. Each field is nil when the
// corresponding feature was not registered (e.g. abuse when no store
// path is configured).
type featureHandles struct {
	blocklist   *blocklist.Feature
	geoip       *featgeoip.Feature
	ratelimit   *featratelimit.Feature
	ttlblock    *featttlblock.Feature
	sanitize    *featsanitize.Feature
	headers     *featheaders.Feature
	abuse       *abuse.Feature
	staticcache *featstaticcache.Feature
}

// NewServer builds the full middleware chain and returns a ready Server.
// It registers every P1 feature against reg, builds the feature chain,
// wraps it with the host router, the admin-gate carve-out, and the
// transport-agnostic outer middlewares. The returned Server still needs
// ListenAndServe / ListenAndServeTLS to run.
//
// Backward compatibility: when reg is nil a fresh registry is created
// internally, and when gate is nil a disabled admin.Gate is substituted;
// pre-P1 single-tenant deployments can therefore still call NewServer
// with only cfg, nil, nil, nil, nil.
func NewServer(cfg *config.Config, t transport.Transport, reg *feature.Registry, gate *admin.Gate, labeler *metrics.Labeler) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("server: cfg is required")
	}
	if reg == nil {
		reg = feature.NewRegistry()
	}
	if gate == nil {
		gate = admin.New(admin.Config{})
	}

	s := &Server{
		cfg:       cfg,
		transport: t,
		registry:  reg,
		adminGate: gate,
		labeler:   labeler,
	}

	// 1. Build the Tor transport — it owns SOCKS5 dialing and retries.
	torTransport := NewTorTransport(cfg, t, s.getPool)
	nc := featnegcache.NewCache(5*time.Minute, 5)
	torTransport.WithNegCache(nc)
	s.negCache = nc
	s.torTransport = torTransport

	// 2. Build the reverse proxy (innermost handler).
	// cfEnabled captures the Cloudflare toggle once at boot; the Director
	// closure uses it to decide whether CF-Connecting-IP survives long
	// enough for TorTransport.RoundTrip to copy it into X-Forwarded-For.
	cfEnabled := cfg.Cloudflare.Enabled
	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			// TorTransport.RoundTrip rewrites URL/Host; Director here only
			// scrubs attacker-controlled forwarding/auth-context headers.
			stripInboundProxyHeaders(req.Header, cfEnabled)
		},
		Transport: torTransport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("reverse proxy error", "err", err, "path", redactPath(s.adminGate, r.URL.Path))
			serveErrorPage(w, http.StatusBadGateway)
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Del("Server")
			resp.Header.Del("X-Powered-By")
			resp.Header.Del("Via")
			// Remove CSP — backend app uses inline scripts that conflict
			// with nonce-based CSP. Let the app handle its own CSP properly.
			resp.Header.Del("Content-Security-Policy")
			return nil
		},
	}

	// 3. Register the P1 feature set against the registry. Order of
	// registration maps to middleware order: first-registered is
	// outermost. We pick the order from the spec's feature-toggle
	// matrix, placing traffic-gating features (blocklist, geoip, rate
	// limit, ttl blocklist) before content-touching ones (headers,
	// sanitize) and the final cache layer.
	handles, err := s.registerFeatures()
	if err != nil {
		return nil, fmt.Errorf("server: register features: %w", err)
	}
	s.featureHandles = handles

	// 4. Build the feature middleware chain around the reverse proxy.
	featureChain := reg.BuildChain(rp)

	// 5. Host router sits between the outer middlewares and the feature
	// chain so feature middlewares can resolve by tenant context.
	var handler http.Handler = HostRouterFromConfig(cfg, reg, featureChain)

	// 6. Legacy-only: the Cloudflare validator still runs outside the
	// feature chain because it operates on the TCP peer (not tenant
	// state). It becomes a no-op when Cloudflare integration is off.
	// The labeler-backed IP hasher ensures raw client IPs never reach
	// the slog sink when a non-CF request is rejected.
	cfValidator := NewCFValidator(cfg.Cloudflare.Enabled)
	var ipHasher func(string) string
	if labeler != nil {
		ipHasher = labeler.ClientIP
	}
	handler = cfValidator.Middleware(ipHasher, handler)

	// 7. Security headers: unconditional hardening that applies to every
	// response regardless of tenant. Wave-3 may move this behind a
	// per-tenant toggle; for now it stays outside the feature chain.
	handler = securityHeadersMiddleware(handler)

	// 8. Max body size (4 MB) — enforced before any tenant-aware code
	// runs so upload-heavy abuse never reaches features/backends.
	handler = maxBodyMiddleware(maxBodyBytes, handler)

	// 9. Recovery: turns downstream panics into 500s. The gate is passed
	// in so the logged path redacts admin slug/tokens when they appear.
	handler = recoveryMiddleware(gate, handler)

	// 10. Metrics: wraps the outermost layer below the admin gate so
	// admin paths are NOT tracked (keeps the gate invisible in exported
	// metrics). The labeler is accepted but not yet threaded into the
	// legacy counter set; wave-3 wiring is tracked separately.
	handler = metricsMiddleware(handler)

	// 11. Admin gate (outermost). MatchesPrefix/ServeHTTP enforce the
	// constant-time carve-out even when the gate is disabled. This
	// MUST be the first thing every request encounters so nothing
	// below sees admin paths.
	handler = adminGateMiddleware(gate, handler)

	s.httpServer = &http.Server{
		Handler:           handler,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 * 1024, // 64 KB
	}

	return s, nil
}

// registerFeatures installs every P1 feature on the server's registry
// and returns handles used by lifecycle hooks. Order in this function
// determines middleware order: the first-registered feature is
// outermost within the feature chain.
func (s *Server) registerFeatures() (featureHandles, error) {
	var h featureHandles
	reg := s.registry

	// Blocklist (regex) — runs earliest so obvious abuse never reaches
	// later features. Self-constructs; no external deps.
	h.blocklist = blocklist.RegisterWith(reg)

	// Rate limiter — after blocklist so rate-limited abusers aren't
	// bucketed before being outright blocked.
	h.ratelimit = featratelimit.NewFeature()
	reg.Register(h.ratelimit)
	reg.AddReloadObserver(h.ratelimit.Name(), func(snap shared.FeatureSnapshot) {
		h.ratelimit.Observe(snap)
		h.ratelimit.ApplyFromSnapshots(reg.Tenants())
	})
	h.ratelimit.Start()

	// GeoIP — country block list. No RegisterWith helper in feature
	// package; we wire the reload observer inline.
	h.geoip = featgeoip.New()
	reg.Register(h.geoip)
	reg.AddReloadObserver(h.geoip.Name(), func(snap shared.FeatureSnapshot) {
		tenants := reg.Tenants()
		tenantFeats := make(map[string]shared.FeatureSnapshot, len(tenants))
		for host, t := range tenants {
			if ts, ok := t.Features[h.geoip.Name()]; ok {
				tenantFeats[host] = ts
			}
		}
		h.geoip.Observe(snap, tenantFeats)
	})

	// TTL blocklist — persistent auto-expiring blocks. Start the
	// sweeper immediately so auto-expiry fires without waiting for the
	// first request. The sweeper lifetime is bound to ctx.Background()
	// here and gets torn down by Server.Shutdown -> Feature.Stop.
	h.ttlblock = featttlblock.New()
	reg.Register(h.ttlblock)
	reg.AddReloadObserver(h.ttlblock.Name(), func(snap shared.FeatureSnapshot) {
		h.ttlblock.Observe(snap)
		h.ttlblock.RegisterTenants(reg.Tenants())
	})
	h.ttlblock.Start(context.Background())

	// Content sanitizer — HTML tag stripping. RegisterWith wires the
	// observer itself.
	h.sanitize = featsanitize.RegisterWith(reg)

	// Proxy headers — add/strip rules.
	h.headers = featheaders.RegisterWith(reg)

	// Abuse reporting endpoint. Attempted only when a store path is
	// configured (bootstrap stub — configured per-deployment later); a
	// missing path surfaces the feature as a disabled pass-through so
	// the registry still validates every Reload against it.
	if abuseF, err := abuse.New(""); err == nil {
		h.abuse = abuse.RegisterWith(reg, abuseF)
	}

	// Static response cache — last-registered so the first-registered
	// feature is outermost and caching sits closest to the backend.
	h.staticcache = featstaticcache.RegisterWith(reg)

	return h, nil
}

// SnapshotClient returns the currently-wired snapshot client, if any.
// Exposed so callers (tests, integration harness) can drive it
// explicitly.
func (s *Server) SnapshotClient() SnapshotClient {
	return s.snapshotClient
}

// SetSnapshotClient replaces the server's snapshot client. Production
// callers typically call NewSnapshotClient directly and pass the result
// here during boot.
func (s *Server) SetSnapshotClient(c SnapshotClient) {
	s.snapshotClient = c
}

// Registry returns the feature registry backing this server so callers
// outside the package (tests, cmd/gateway-proxy) can wire additional
// features or drive reloads.
func (s *Server) Registry() *feature.Registry {
	return s.registry
}

// AdminGate returns the gate so callers can introspect its enabled
// state without exposing the secret fields.
func (s *Server) AdminGate() *admin.Gate {
	return s.adminGate
}

// Labeler returns the metrics labeler (nil when disabled). Exposed so
// callers that export their own metrics can reuse the same hashing.
func (s *Server) Labeler() *metrics.Labeler {
	return s.labeler
}

// NegCache returns the negative-cache instance wired into TorTransport.
// Exposed for admin tooling that wants to inspect or reset state.
func (s *Server) NegCache() *featnegcache.Cache {
	return s.negCache
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

	// HTTP->HTTPS redirect + ACME challenge handler on :80. See
	// newRedirectServer for the timeout policy and rationale.
	s.redirectServer = newRedirectServer(":80", domain)
	go func() {
		if err := s.redirectServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP redirect listener failed", "error", err)
		}
	}()

	slog.Info("gateway-proxy TLS listening", "domain", domain)
	return s.httpServer.Serve(ln)
}

// Shutdown gracefully stops the server using the provided context.
//
// Ordering is deliberate: stop accepting first, then reverse-unwind the
// feature lifecycle so no closer observes a concurrent request. Steps:
//
//  1. http.Server.Shutdown — stop accepting new requests and wait for
//     in-flight ones up to ctx's deadline.
//  2. Feature closers in reverse registration order:
//     ttlblock (Stop sweeper + SetStore(nil) to close BoltDB),
//     abuse (Close release store file),
//     geoip (Close mmdb readers),
//     ratelimit (Stop sweeper; cleanup goroutine already stops here).
//  3. SnapshotClient.Close when set.
//  4. Transport.Close to release overlay / idle connections.
//
// Errors are collected but subsequent steps still run; the first
// non-nil error (or http.Server.Shutdown's error) is returned so a
// caller's logs surface the most actionable symptom.
func (s *Server) Shutdown(ctx context.Context) error {
	// 1. Stop accepting requests.
	httpErr := s.httpServer.Shutdown(ctx)

	// 1b. Stop the :80 ACME/redirect listener if one is running. Errors
	// here are logged-only because the main TLS listener's shutdown
	// status is the actionable signal.
	if s.redirectServer != nil {
		if err := s.redirectServer.Shutdown(ctx); err != nil && err != http.ErrServerClosed {
			slog.Warn("redirect server shutdown", "error", err)
		}
	}

	// 2. Tear down features in reverse registration order. The order
	// below mirrors registerFeatures: last-registered features are
	// closed first so that earlier features never see a partially
	// torn-down dependency.
	if s.featureHandles.ttlblock != nil {
		s.featureHandles.ttlblock.Stop()
		// SetStore(nil) closes the currently-open BoltDB file; this is
		// what releases the on-disk handle so deleting the file post
		// shutdown is safe.
		s.featureHandles.ttlblock.SetStore(nil)
	}
	if s.featureHandles.abuse != nil {
		_ = s.featureHandles.abuse.Close()
	}
	if s.featureHandles.geoip != nil {
		_ = s.featureHandles.geoip.Close()
	}
	if s.featureHandles.ratelimit != nil {
		s.featureHandles.ratelimit.Stop()
	}

	// 3. Close the snapshot client (stops reconnect loop, subscriber).
	if s.snapshotClient != nil {
		_ = s.snapshotClient.Close()
	}

	// 4. Drain the inner TorTransport first so its per-port
	// *http.Transport idle-conn pools are released before the overlay
	// transport goes away underneath them.
	if s.torTransport != nil {
		_ = s.torTransport.Close()
	}

	// 5. Close the outer transport — drops overlay sockets and any idle
	// connections not owned by TorTransport.
	if s.transport != nil {
		_ = s.transport.Close()
	}

	return httpErr
}

// ServeHTTP lets tests drive the full middleware stack without binding
// a listener. The installed handler already includes the admin gate, so
// this function is a simple passthrough for introspection.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.httpServer.Handler.ServeHTTP(w, r)
}

// adminGateMiddleware runs the constant-time gate check. Matching paths
// are served by gate.ServeHTTP (501 in P1), everything else falls
// through to next. Disabled gates always fall through.
func adminGateMiddleware(gate *admin.Gate, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if gate != nil && gate.MatchesPrefix(r.URL.Path) {
			gate.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
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

// SetPoolCache replaces the cached pool snapshot. Intended for tests
// that need deterministic backend lists without running the pool
// poller.
func (s *Server) SetPoolCache(pool []shared.BackendInfo) {
	s.mu.Lock()
	s.poolCache = append(s.poolCache[:0], pool...)
	s.mu.Unlock()
}

// inboundProxyHeaders is the full set of forwarding / proxy-auth-context
// headers the Director scrubs from every inbound request. Backends that
// rely on any of these to identify the real client must instead read the
// X-Forwarded-For value our trusted TorTransport.RoundTrip writes.
//
// CF-Connecting-IP is NOT in this list; it is handled separately based on
// whether the Cloudflare validator is enabled (see stripInboundProxyHeaders).
var inboundProxyHeaders = []string{
	"Forwarded",
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
	"X-Forwarded-Port",
	"X-Real-IP",
	"X-Real-Port",
	"X-Original-URL",
	"X-Rewrite-URL",
	"X-Original-Host",
	"True-Client-IP",
	"CF-Ray",
	"CF-Visitor",
	"Fastly-Client-IP",
	"X-Client-IP",
	"X-Cluster-Client-IP",
	"Via",
	"X-Proxy-Secret",
}

// newRedirectServer builds the :80 ACME-challenge / HTTPS-redirect
// server with mandatory timeouts. Unbounded timeouts on this listener
// are an availability bug: a slowloris client can occupy every
// connection slot and silently break ACME renewal, which then breaks
// TLS the next time CertMagic tries to refresh.
//
// Redirect target uses domain (not r.Host) because r.Host is
// attacker-controlled — using it would let an attacker redirect clients
// to an arbitrary host.
func newRedirectServer(addr, domain string) *http.Server {
	redirectHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := "https://" + domain + r.RequestURI
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
	return &http.Server{
		Addr:              addr,
		Handler:           certmagic.DefaultACME.HTTPChallengeHandler(redirectHandler),
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
}

// stripInboundProxyHeaders removes attacker-controlled forwarding headers
// from h so a backend can never confuse a spoofed value with a value
// stamped by our trusted TorTransport. Called once per request from the
// reverse-proxy Director.
//
// CF-Connecting-IP policy: when cfEnabled is true the Cloudflare validator
// upstream has already verified the connection originates from a CF range,
// so we leave the header in place for TorTransport.RoundTrip (transport.go)
// to copy into X-Forwarded-For. When cfEnabled is false there is no such
// validation, so we strip CF-Connecting-IP unconditionally to prevent
// auth-context smuggling via that name.
func stripInboundProxyHeaders(h http.Header, cfEnabled bool) {
	for _, name := range inboundProxyHeaders {
		h.Del(name)
	}
	if !cfEnabled {
		h.Del("CF-Connecting-IP")
	}
}
