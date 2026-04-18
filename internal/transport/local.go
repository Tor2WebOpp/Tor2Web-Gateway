package transport

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// Default values for LocalConfig. Exposed so callers and tests can reason
// about timings without inspecting defaults applied in NewLocal.
const (
	defaultLocalSOCKSHost     = "127.0.0.1"
	defaultLocalDialTimeout   = 2 * time.Second
	defaultLocalClientTimeout = 5 * time.Second
)

// LocalConfig parameterises the same-machine Transport. Zero values for
// the three non-path fields fall back to sensible defaults in NewLocal.
type LocalConfig struct {
	// SocketPath is the absolute filesystem path of the gateway-torpool
	// admin unix socket. Required; NewLocal does not synthesise one.
	SocketPath string

	// SOCKSHost is the loopback address at which Tor SOCKS5 ports are
	// bound. Defaults to "127.0.0.1" when empty.
	SOCKSHost string

	// DialTimeout bounds each TCP (SOCKS) and unix (admin) dial attempt.
	// Defaults to 2s when zero.
	DialTimeout time.Duration

	// ClientTimeout is the overall request timeout applied to the
	// AdminClient *http.Client. Defaults to 5s when zero.
	ClientTimeout time.Duration
}

// Local is the wave 1 Transport implementation for single-machine
// deployments. It is drop-in compatible with the existing code paths in
// internal/proxy: DialSOCKS mirrors the 127.0.0.1:<port> dial in
// proxy/transport.go, and AdminClient mirrors the unix-socket http.Client
// built inside (*proxy.Server).PollPool.
type Local struct {
	cfg        LocalConfig
	httpClient *http.Client
	transport  *http.Transport

	closed atomic.Bool
}

// NewLocal returns a Local Transport using the supplied config. Defaults
// are filled in for SOCKSHost, DialTimeout, and ClientTimeout; SocketPath
// is passed through unchanged (an empty SocketPath is accepted here and
// will surface as a dial error at first AdminClient use, matching the
// lazy-failure posture of the rest of the gateway).
func NewLocal(cfg LocalConfig) *Local {
	if cfg.SOCKSHost == "" {
		cfg.SOCKSHost = defaultLocalSOCKSHost
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = defaultLocalDialTimeout
	}
	if cfg.ClientTimeout <= 0 {
		cfg.ClientTimeout = defaultLocalClientTimeout
	}

	socketPath := cfg.SocketPath
	dialTimeout := cfg.DialTimeout

	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: dialTimeout}
			return d.DialContext(ctx, "unix", socketPath)
		},
	}

	httpClient := &http.Client{
		Transport: tr,
		Timeout:   cfg.ClientTimeout,
	}

	return &Local{
		cfg:        cfg,
		httpClient: httpClient,
		transport:  tr,
	}
}

// DialSOCKS dials the loopback SOCKS5 port of a Tor instance. It honors
// ctx cancellation and the configured DialTimeout, whichever fires first.
func (l *Local) DialSOCKS(ctx context.Context, port int) (net.Conn, error) {
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("transport/local: dial socks: invalid port %d", port)
	}
	d := net.Dialer{Timeout: l.cfg.DialTimeout}
	addr := fmt.Sprintf("%s:%d", l.cfg.SOCKSHost, port)
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("transport/local: dial socks %s: %w", addr, err)
	}
	return conn, nil
}

// AdminClient returns the shared *http.Client whose Transport always dials
// the configured unix socket. The returned client is safe for concurrent
// use but must not be mutated by callers.
func (l *Local) AdminClient() *http.Client {
	return l.httpClient
}

// Close closes idle connections on the admin client's http.Transport.
// Safe to call more than once; subsequent calls are no-ops and return
// nil.
func (l *Local) Close() error {
	if l.closed.Swap(true) {
		return nil
	}
	if l.transport != nil {
		l.transport.CloseIdleConnections()
	}
	return nil
}

// Compile-time assertion that *Local satisfies Transport.
var _ Transport = (*Local)(nil)
