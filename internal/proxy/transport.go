package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"gateway/internal/config"
	"gateway/internal/shared"

	"github.com/sony/gobreaker/v2"
	"golang.org/x/net/proxy"
)

const maxResponseBytes = 50 * 1024 * 1024 // 50 MB

// limitedBody wraps a limited reader while preserving the original Closer.
type limitedBody struct {
	io.Reader
	io.Closer
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

// TorTransport implements http.RoundTripper, routing requests through SOCKS5
// Tor proxies with circuit breaking and retry logic.
type TorTransport struct {
	cfg          *config.Config
	mu           sync.Mutex
	transports   map[int]*http.Transport
	breakers     map[int]*gobreaker.CircuitBreaker[*http.Response]
	poolFetcher  func() []shared.BackendInfo
}

// NewTorTransport creates a TorTransport with the given config and pool fetcher.
func NewTorTransport(cfg *config.Config, poolFetcher func() []shared.BackendInfo) *TorTransport {
	return &TorTransport{
		cfg:         cfg,
		transports:  make(map[int]*http.Transport),
		breakers:    make(map[int]*gobreaker.CircuitBreaker[*http.Response]),
		poolFetcher: poolFetcher,
	}
}

// getTransport lazily creates and caches an http.Transport + circuit breaker for port.
func (t *TorTransport) getTransport(port int) (*http.Transport, *gobreaker.CircuitBreaker[*http.Response]) {
	t.mu.Lock()
	defer t.mu.Unlock()

	tr, ok := t.transports[port]
	if !ok {
		socksAddr := fmt.Sprintf("127.0.0.1:%d", port)
		dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
		if err != nil {
			// fallback: use direct transport (should not happen with static args)
			tr = &http.Transport{}
		} else {
			cd, ok := dialer.(proxy.ContextDialer)
			if !ok {
				tr = &http.Transport{}
			} else {
				tr = &http.Transport{
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						return cd.DialContext(ctx, network, addr)
					},
					MaxIdleConnsPerHost: t.cfg.Pool.MaxIdleConnsPerHost,
					IdleConnTimeout:     t.cfg.Pool.IdleTimeout,
					ResponseHeaderTimeout: t.cfg.Pool.ResponseTimeout,
				}
			}
		}
		t.transports[port] = tr
	}

	cb, ok := t.breakers[port]
	if !ok {
		settings := gobreaker.Settings{
			Name:        fmt.Sprintf("tor-%d", port),
			MaxRequests: 3,
			Interval:    30 * time.Second,
			Timeout:     15 * time.Second,
			ReadyToTrip: func(counts gobreaker.Counts) bool {
				return counts.Requests >= 10 &&
					float64(counts.TotalFailures)/float64(counts.Requests) >= 0.5
			},
		}
		cb = gobreaker.NewCircuitBreaker[*http.Response](settings)
		t.breakers[port] = cb
	}

	return tr, cb
}

// RemoveTransport closes idle connections and removes the cached transport and
// circuit breaker for the given port. This prevents stale entries from
// accumulating when instances are replaced.
func (t *TorTransport) RemoveTransport(port int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if tr, ok := t.transports[port]; ok {
		tr.CloseIdleConnections()
		delete(t.transports, port)
	}
	delete(t.breakers, port)
}

// RoundTrip implements http.RoundTripper.
func (t *TorTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	pool := t.poolFetcher()

	tried := make(map[int]bool)
	maxAttempts := t.cfg.Pool.RetryAttempts
	if maxAttempts <= 0 {
		maxAttempts = 3
	}

	var lastErr error

	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Build a filtered pool excluding already-tried ports.
		available := make([]shared.BackendInfo, 0, len(pool))
		for _, b := range pool {
			if !tried[b.Port] {
				available = append(available, b)
			}
		}

		backend := selectBackend(available)
		if backend == nil {
			break
		}
		tried[backend.Port] = true

		tr, cb := t.getTransport(backend.Port)

		// Clone request and rewrite for .onion backend.
		outReq := req.Clone(req.Context())
		outReq.URL.Scheme = "http"
		outReq.URL.Host = backend.Backend
		outReq.Host = backend.Backend

		// Inject proxy headers.
		outReq.Header.Set("X-Proxy-Secret", t.cfg.ProxySecret)
		if cf := req.Header.Get("CF-Connecting-IP"); cf != "" {
			outReq.Header.Set("X-Forwarded-For", cf)
		}
		outReq.Header.Set("X-Forwarded-Proto", "https")

		resp, err := cb.Execute(func() (*http.Response, error) {
			return tr.RoundTrip(outReq)
		})

		if err != nil {
			lastErr = err
			continue
		}

		// Retry only on gateway-error statuses; pass everything else through.
		if !isRetryableStatus(resp.StatusCode) {
			if resp.Body != nil {
				resp.Body = &limitedBody{
					Reader: io.LimitReader(resp.Body, maxResponseBytes),
					Closer: resp.Body,
				}
			}
			return resp, nil
		}
		resp.Body.Close()
		lastErr = fmt.Errorf("upstream returned %d", resp.StatusCode)
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no alive backends available")
}

// isRetryableStatus returns true for HTTP status codes that warrant a retry
// on a different backend (502 Bad Gateway, 503 Service Unavailable, 504 Gateway Timeout).
func isRetryableStatus(code int) bool {
	return code == 502 || code == 503 || code == 504
}
