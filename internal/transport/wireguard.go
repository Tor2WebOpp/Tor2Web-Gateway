package transport

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync/atomic"
	"time"

	"gateway/internal/config"
)

// Default values for WireguardConfig. Exposed so callers and tests can
// reason about timings without inspecting defaults applied in NewWireguard.
const (
	defaultWireguardAdminPort     = 9080
	defaultWireguardDialTimeout   = 2 * time.Second
	defaultWireguardClientTimeout = 5 * time.Second
)

// WireguardConfig parameterises the remote-hub Transport that rides on an
// externally managed WireGuard interface. This transport does not bring
// the wg interface up — that is the installer's responsibility. The
// struct therefore carries only the values we need to dial the hub over
// the overlay once it is up.
type WireguardConfig struct {
	// Interface is the wg interface name (e.g. "wg0"). Recorded for
	// diagnostics; not required for dialing because the kernel routes
	// based on PeerInternalIP/AllowedIPs.
	Interface string

	// PrivateKeyFile is the path to the wg-quick private key. Recorded
	// for diagnostics; the transport does not read it.
	PrivateKeyFile string

	// PeerPubkey is the hub's WireGuard public key. Recorded for
	// diagnostics only.
	PeerPubkey string

	// PeerEndpoint is the hub's public wg endpoint (host:port).
	// Recorded for diagnostics only; kernel wg handles the handshake.
	PeerEndpoint string

	// PeerAllowedIPs is the CIDR of hub-side addresses reachable over
	// the overlay. Recorded for diagnostics only.
	PeerAllowedIPs string

	// SelfIP is this edge's overlay address (e.g. "10.0.0.42/24").
	// Recorded for diagnostics only.
	SelfIP string

	// PeerInternalIP is the hub's address on the overlay, bare (no
	// mask), e.g. "10.0.0.1". All SOCKS and admin dials target this
	// address. Required.
	PeerInternalIP string

	// AdminPort is the TCP port on PeerInternalIP where the hub admin
	// HTTP API listens. Defaults to 9080 when zero.
	AdminPort int

	// DialTimeout bounds each TCP dial attempt, both for SOCKS and
	// admin-API calls. Defaults to 2s when zero.
	DialTimeout time.Duration

	// ClientTimeout is the overall request timeout applied to the
	// AdminClient *http.Client. Defaults to 5s when zero.
	ClientTimeout time.Duration
}

// Wireguard is the remote-mode Transport that rides on an externally
// managed WireGuard overlay. DialSOCKS issues plain net.Dial TCP calls
// to PeerInternalIP because the kernel wg interface is expected to be
// up and routing for us; this type never shells out to wg-quick.
type Wireguard struct {
	cfg        WireguardConfig
	httpClient *http.Client
	transport  *http.Transport

	closed atomic.Bool
}

// NewWireguard returns a Wireguard Transport using the supplied config.
// Defaults are filled in for AdminPort, DialTimeout, and ClientTimeout.
// PeerInternalIP is the only strictly required field; an empty value is
// rejected up front because every method would otherwise fail with the
// same misleading dial error.
func NewWireguard(cfg WireguardConfig) (*Wireguard, error) {
	if cfg.PeerInternalIP == "" {
		return nil, fmt.Errorf("transport/wireguard: peer_internal_ip is required")
	}
	if cfg.AdminPort <= 0 {
		cfg.AdminPort = defaultWireguardAdminPort
	}
	if cfg.AdminPort > 65535 {
		return nil, fmt.Errorf("transport/wireguard: admin_port %d out of range", cfg.AdminPort)
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = defaultWireguardDialTimeout
	}
	if cfg.ClientTimeout <= 0 {
		cfg.ClientTimeout = defaultWireguardClientTimeout
	}

	adminAddr := net.JoinHostPort(cfg.PeerInternalIP, strconv.Itoa(cfg.AdminPort))
	dialTimeout := cfg.DialTimeout

	// DialContext ignores the address the stdlib would derive from the
	// request URL and always targets the hub's overlay address. This
	// lets callers pass any host they want in the URL (hostnames aren't
	// resolvable on the overlay) and still hit the right endpoint.
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: dialTimeout}
			return d.DialContext(ctx, "tcp", adminAddr)
		},
	}

	httpClient := &http.Client{
		Transport: tr,
		Timeout:   cfg.ClientTimeout,
	}

	return &Wireguard{
		cfg:        cfg,
		httpClient: httpClient,
		transport:  tr,
	}, nil
}

// DialSOCKS dials the SOCKS5 port of a Tor instance on the hub. It
// honors ctx cancellation and the configured DialTimeout, whichever
// fires first.
func (w *Wireguard) DialSOCKS(ctx context.Context, port int) (net.Conn, error) {
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("transport/wireguard: dial socks: invalid port %d", port)
	}
	d := net.Dialer{Timeout: w.cfg.DialTimeout}
	addr := net.JoinHostPort(w.cfg.PeerInternalIP, strconv.Itoa(port))
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("transport/wireguard: dial socks %s: %w", addr, err)
	}
	return conn, nil
}

// AdminClient returns the shared *http.Client whose Transport always
// dials the hub admin endpoint over the overlay. The returned client
// is safe for concurrent use but must not be mutated by callers.
func (w *Wireguard) AdminClient() *http.Client {
	return w.httpClient
}

// Close closes idle connections on the admin client's http.Transport.
// Safe to call more than once; subsequent calls are no-ops and return
// nil.
func (w *Wireguard) Close() error {
	if w.closed.Swap(true) {
		return nil
	}
	if w.transport != nil {
		w.transport.CloseIdleConnections()
	}
	return nil
}

// ParseWireguardConfigFromTop builds a WireguardConfig from the
// top-level *config.Config. It pulls the wg-specific fields from
// config.Transport.Wireguard and derives PeerInternalIP and AdminPort
// from the hub_url when present, so that operators only have to set
// hub_url once in bootstrap YAML.
func ParseWireguardConfigFromTop(topCfg *config.Config) (WireguardConfig, error) {
	if topCfg == nil {
		return WireguardConfig{}, fmt.Errorf("transport/wireguard: nil config")
	}
	wgCfg := topCfg.Transport.Wireguard

	out := WireguardConfig{
		Interface:      wgCfg.Interface,
		PrivateKeyFile: wgCfg.PrivateKeyFile,
		PeerPubkey:     wgCfg.PeerPubkey,
		PeerEndpoint:   wgCfg.PeerEndpoint,
		PeerAllowedIPs: wgCfg.PeerAllowedIPs,
		SelfIP:         wgCfg.SelfIP,
	}

	if topCfg.HubURL != "" {
		u, err := url.Parse(topCfg.HubURL)
		if err != nil {
			return WireguardConfig{}, fmt.Errorf("transport/wireguard: parse hub_url %q: %w", topCfg.HubURL, err)
		}
		host := u.Hostname()
		if host == "" {
			return WireguardConfig{}, fmt.Errorf("transport/wireguard: hub_url %q has no host", topCfg.HubURL)
		}
		out.PeerInternalIP = host
		if p := u.Port(); p != "" {
			port, err := strconv.Atoi(p)
			if err != nil {
				return WireguardConfig{}, fmt.Errorf("transport/wireguard: hub_url port %q: %w", p, err)
			}
			out.AdminPort = port
		}
	}

	if out.PeerInternalIP == "" {
		return WireguardConfig{}, fmt.Errorf("transport/wireguard: hub_url is required to derive peer_internal_ip")
	}

	return out, nil
}

// Compile-time assertion that *Wireguard satisfies Transport.
var _ Transport = (*Wireguard)(nil)
