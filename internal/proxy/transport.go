package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gateway/internal/config"
	"gateway/internal/feature"
	"gateway/internal/feature/negcache"
	"gateway/internal/shared"
	"gateway/internal/transport"

	"github.com/sony/gobreaker/v2"
)

// maxResponseBytes is the default ceiling applied to buffered / non-streaming
// responses to prevent runaway backend replies from consuming edge memory.
// TODO: expose as cfg.Pool.MaxResponseBytes (default 50 MB, zero means
// unlimited) once the config surface is extended in a follow-up wave.
const maxResponseBytes = 50 * 1024 * 1024 // 50 MB

// limitedBody wraps a limited reader while preserving the original Closer.
// The atomic counter lets Read emit a slog.Warn exactly once if the cap
// truncated the stream, rather than silently dropping data.
type limitedBody struct {
	io.Reader
	io.Closer
	read    atomic.Int64
	limit   int64
	logOnce sync.Once
	path    string
}

// Read proxies the underlying reader and warns (at most once) when EOF
// coincides with having hit the byte cap — a reliable signal that the
// body was truncated rather than naturally ended.
func (l *limitedBody) Read(p []byte) (int, error) {
	n, err := l.Reader.Read(p)
	if n > 0 {
		l.read.Add(int64(n))
	}
	if err == io.EOF && l.read.Load() >= l.limit {
		l.logOnce.Do(func() {
			slog.Warn("response truncated at max_response_bytes",
				"limit_bytes", l.limit,
				"path", l.path)
		})
	}
	return n, err
}

// shouldStream reports whether the given response should bypass the
// max-response-bytes cap. Streaming content types (SSE) and chunked
// transfer encoding are allowed to pass through unmodified; everything
// else is clamped.
func shouldStream(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	ct := resp.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "text/event-stream") {
		return true
	}
	// Transfer-Encoding is sometimes a list ("chunked, gzip"); check each
	// token. net/http canonicalises case.
	for _, te := range resp.TransferEncoding {
		if strings.EqualFold(te, "chunked") {
			return true
		}
	}
	if strings.EqualFold(resp.Header.Get("Transfer-Encoding"), "chunked") {
		return true
	}
	return false
}

// selectBackend picks the alive backend with the lowest Score().
// Returns nil if no alive backends exist.
func selectBackend(pool []shared.BackendInfo) *shared.BackendInfo {
	var best *shared.BackendInfo
	for i := range pool {
		b := &pool[i]
		if !b.Alive {
			continue
		}
		if best == nil || b.Score() < best.Score() {
			best = b
		}
	}
	return best
}

// breakerKey identifies a circuit breaker by (SOCKS port, backend onion).
// Keying on the pair prevents one failing onion from tripping the breaker
// for every other backend that happens to share the same Tor instance.
type breakerKey struct {
	port    int
	backend string
}

// TorTransport implements http.RoundTripper, routing requests through
// SOCKS5 Tor proxies with circuit breaking, retry logic, and negative
// cache integration.
type TorTransport struct {
	cfg         *config.Config
	tport       transport.Transport
	mu          sync.Mutex
	transports  map[int]*http.Transport
	breakers    map[breakerKey]*gobreaker.CircuitBreaker[*http.Response]
	poolFetcher func() []shared.BackendInfo

	// negCache tracks backend failures keyed by (tenant, onion). Nil
	// disables negative caching. It is consulted before RoundTrip to
	// skip blacklisted backends and updated afterward on success or
	// failure.
	negCache *negcache.Cache
}

// NewTorTransport creates a TorTransport with the given config, the
// chosen transport.Transport (for SOCKS5 dialing), and a fetcher that
// returns the latest pool snapshot from gateway-torpool.
//
// When t is nil the transport falls back to the pre-P1 behaviour of
// dialing 127.0.0.1 directly, matching wave 1's single-machine mode.
func NewTorTransport(cfg *config.Config, t transport.Transport, poolFetcher func() []shared.BackendInfo) *TorTransport {
	return &TorTransport{
		cfg:         cfg,
		tport:       t,
		transports:  make(map[int]*http.Transport),
		breakers:    make(map[breakerKey]*gobreaker.CircuitBreaker[*http.Response]),
		poolFetcher: poolFetcher,
	}
}

// WithNegCache wires a negative-cache instance into the transport so
// that backends blacklisted by previous failures are skipped before a
// SOCKS dial is attempted. Returns t for chaining.
func (t *TorTransport) WithNegCache(c *negcache.Cache) *TorTransport {
	t.mu.Lock()
	t.negCache = c
	t.mu.Unlock()
	return t
}

// getTransport lazily creates and caches an http.Transport + circuit
// breaker for (port, backend). The dial function uses the configured
// transport.Transport so both local (loopback) and remote (overlay)
// deployments share the same code path.
//
// The breaker is keyed on (port, backend) so one failing .onion cannot
// trip the breaker for every other backend sharing the same Tor port.
func (t *TorTransport) getTransport(port int, backend string) (*http.Transport, *gobreaker.CircuitBreaker[*http.Response]) {
	t.mu.Lock()
	defer t.mu.Unlock()

	tr, ok := t.transports[port]
	if !ok {
		tr = t.buildTransportLocked(port)
		t.transports[port] = tr
	}

	key := breakerKey{port: port, backend: backend}
	cb, ok := t.breakers[key]
	if !ok {
		settings := gobreaker.Settings{
			Name:        fmt.Sprintf("tor-%d-%s", port, backend),
			MaxRequests: 3,
			Interval:    30 * time.Second,
			Timeout:     15 * time.Second,
			ReadyToTrip: func(counts gobreaker.Counts) bool {
				return counts.Requests >= 10 &&
					float64(counts.TotalFailures)/float64(counts.Requests) >= 0.5
			},
		}
		cb = gobreaker.NewCircuitBreaker[*http.Response](settings)
		t.breakers[key] = cb
	}

	return tr, cb
}

// buildTransportLocked builds an *http.Transport whose DialContext
// routes through the configured transport.Transport. The caller must
// hold t.mu.
func (t *TorTransport) buildTransportLocked(port int) *http.Transport {
	dialer := t.tport
	return &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			if dialer == nil {
				// Pre-P1 fallback: dial loopback SOCKS5 directly. Used
				// by tests that do not build a full transport.
				d := net.Dialer{Timeout: 2 * time.Second}
				return d.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
			}
			return dialer.DialSOCKS(ctx, port)
		},
		MaxIdleConnsPerHost:   t.cfg.Pool.MaxIdleConnsPerHost,
		IdleConnTimeout:       t.cfg.Pool.IdleTimeout,
		ResponseHeaderTimeout: t.cfg.Pool.ResponseTimeout,
	}
}

// RemoveTransport closes idle connections and removes the cached
// transport and all circuit breakers associated with the given port. This
// prevents stale entries from accumulating when Tor instances are
// replaced. Because breakers are keyed per (port, backend), every breaker
// whose port matches is evicted so new instances on the same port start
// fresh.
func (t *TorTransport) RemoveTransport(port int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if tr, ok := t.transports[port]; ok {
		tr.CloseIdleConnections()
		delete(t.transports, port)
	}
	for k := range t.breakers {
		if k.port == port {
			delete(t.breakers, k)
		}
	}
}

// Close drains every cached *http.Transport (closing pooled idle conns)
// and clears the breaker map. The outer transport.Transport remains the
// Server's responsibility; this method only tears down the TorTransport's
// own per-port cache so nothing leaks across a Server.Shutdown.
func (t *TorTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	for port, tr := range t.transports {
		tr.CloseIdleConnections()
		delete(t.transports, port)
	}
	for k := range t.breakers {
		delete(t.breakers, k)
	}
	return nil
}

// tenantBackendsFromContext extracts the per-tenant backend onion list
// attached by the host router. Returns nil when no tenant is present or
// when the tenant has no explicit backends (in which case callers fall
// back to the global pool).
//
// NOTE: TenantSnapshot does not carry the backend list in P1's feature
// layer — the hub stream ships BackendRef separately. Until a dedicated
// backend-pool abstraction lands in wave 3, we derive the tenant's
// backend list from the cfg.Backends legacy field in local mode. Remote
// mode tenants retain the global pool (which the hub's Tor pool owns).
func (t *TorTransport) tenantBackendsFromContext(r *http.Request) []string {
	tenant := feature.TenantFromContext(r.Context())
	if tenant == nil {
		return nil
	}
	// Legacy single-tenant mode plumbs cfg.Backends through the
	// implicit "default" tenant; use that list when present.
	if len(t.cfg.Backends) > 0 {
		out := make([]string, 0, len(t.cfg.Backends))
		for _, b := range t.cfg.Backends {
			out = append(out, b.Addr)
		}
		return out
	}
	return nil
}

// RoundTrip implements http.RoundTripper.
func (t *TorTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	pool := t.poolFetcher()
	tenantBackends := t.tenantBackendsFromContext(req)

	tried := make(map[int]bool)
	maxAttempts := t.cfg.Pool.RetryAttempts
	if maxAttempts <= 0 {
		maxAttempts = 3
	}

	var lastErr error

	tenant := feature.TenantFromContext(req.Context())
	tenantKey := ""
	if tenant != nil {
		tenantKey = tenant.Host
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Build a filtered pool excluding already-tried ports and any
		// backends whose (tenant, onion) is negatively cached.
		available := make([]shared.BackendInfo, 0, len(pool))
		for _, b := range pool {
			if tried[b.Port] {
				continue
			}
			if t.negCache != nil && b.Backend != "" {
				if t.negCache.IsBlacklisted(tenantKey, b.Backend) {
					continue
				}
			}
			available = append(available, b)
		}

		backend := t.selectTenantBackend(available, tenantBackends)
		if backend == nil {
			break
		}
		tried[backend.Port] = true

		tr, cb := t.getTransport(backend.Port, backend.Backend)

		// Clone request and rewrite for .onion backend.
		// URL.Host = .onion (where to connect), but Host header = original domain
		// so gate sets cookies on the correct domain for the browser.
		outReq := req.Clone(req.Context())
		outReq.URL.Scheme = "http"
		outReq.URL.Host = backend.Backend
		// Preserve the incoming Host so cookies and backend-side
		// routing keep working; in multi-tenant mode this is the
		// tenant's public host, in legacy mode it's cfg.Domain.
		if tenant != nil && tenant.Host != "" {
			outReq.Host = tenant.Host
		} else {
			outReq.Host = t.cfg.Domain
		}

		// Inject proxy headers.
		if t.cfg.ProxySecret != "" {
			outReq.Header.Set("X-Proxy-Secret", t.cfg.ProxySecret)
		}
		if cf := req.Header.Get("CF-Connecting-IP"); cf != "" {
			outReq.Header.Set("X-Forwarded-For", cf)
		}
		outReq.Header.Set("X-Forwarded-Proto", "https")

		resp, err := cb.Execute(func() (*http.Response, error) {
			return tr.RoundTrip(outReq)
		})

		if err != nil {
			lastErr = err
			t.recordFailure(tenantKey, backend.Backend)
			continue
		}

		// Retry only on gateway-error statuses; pass everything else through.
		if !isRetryableStatus(resp.StatusCode) {
			if resp.Body != nil && !shouldStream(resp) {
				resp.Body = &limitedBody{
					Reader: io.LimitReader(resp.Body, maxResponseBytes),
					Closer: resp.Body,
					limit:  maxResponseBytes,
					path:   req.URL.Path,
				}
			}
			t.recordSuccess(tenantKey, backend.Backend)
			return resp, nil
		}
		resp.Body.Close()
		t.recordFailure(tenantKey, backend.Backend)
		lastErr = fmt.Errorf("upstream returned %d", resp.StatusCode)
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no alive backends available")
}

// selectTenantBackend picks a backend from pool, preferring entries
// whose onion address appears in the tenant's explicit backend list.
// When the tenant has no explicit backends (or none of them appear in
// the live pool) the function falls back to the lowest-score pool
// entry, preserving the single-tenant behaviour.
func (t *TorTransport) selectTenantBackend(pool []shared.BackendInfo, tenantBackends []string) *shared.BackendInfo {
	if len(tenantBackends) == 0 {
		return selectBackend(pool)
	}
	want := make(map[string]struct{}, len(tenantBackends))
	for _, a := range tenantBackends {
		want[a] = struct{}{}
	}
	// Prefer backends whose onion appears in the tenant's allowed list.
	filtered := make([]shared.BackendInfo, 0, len(pool))
	for _, b := range pool {
		if _, ok := want[b.Backend]; ok {
			filtered = append(filtered, b)
		}
	}
	if picked := selectBackend(filtered); picked != nil {
		return picked
	}
	// Fall back to the global pool so a misconfigured tenant does not
	// surface 502s purely because its preferred onions are cold.
	return selectBackend(pool)
}

// recordFailure updates the negative cache for (tenant, onion) when
// negcache is wired. No-op when negCache is nil or onion is empty.
func (t *TorTransport) recordFailure(tenant, onion string) {
	if t.negCache == nil || onion == "" {
		return
	}
	t.negCache.RecordFailure(tenant, onion)
}

// recordSuccess clears any outstanding failure counter for (tenant,
// onion) so a recovered backend leaves the blacklist on the first good
// response.
func (t *TorTransport) recordSuccess(tenant, onion string) {
	if t.negCache == nil || onion == "" {
		return
	}
	t.negCache.RecordSuccess(tenant, onion)
}

// isRetryableStatus returns true for HTTP status codes that warrant a retry
// on a different backend (502 Bad Gateway, 503 Service Unavailable, 504 Gateway Timeout).
func isRetryableStatus(code int) bool {
	return code == 502 || code == 503 || code == 504
}
