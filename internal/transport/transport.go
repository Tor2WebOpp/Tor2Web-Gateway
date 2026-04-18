package transport

import (
	"context"
	"net"
	"net/http"
)

// Kind identifies a transport implementation selected at bootstrap. It
// mirrors the string values accepted by the bootstrap config's
// transport.kind field so that config-to-transport construction is a single
// lookup.
type Kind string

// Transport kinds. KindLocal is the wave 1 same-machine implementation;
// the remaining three are wave 2 (remote hub mode).
const (
	KindLocal       Kind = "local"
	KindWireguard   Kind = "wireguard"
	KindHTTPSTunnel Kind = "https_tunnel"
	KindSOCKS5TLS   Kind = "socks5_tls"
)

// Transport is the reachability abstraction between an edge gateway and the
// hub that owns the Tor pool and the admin API. Implementations must be
// safe for concurrent use by multiple goroutines.
type Transport interface {
	// DialSOCKS returns a net.Conn to a SOCKS5 endpoint on the given port.
	// In Local mode, dials 127.0.0.1:<port>. In remote modes, dials
	// through the overlay (wg/https-tunnel/socks5-tls) so that the caller
	// sees the same net.Conn semantics regardless of transport.
	DialSOCKS(ctx context.Context, port int) (net.Conn, error)

	// AdminClient returns an *http.Client that reaches the hub admin HTTP
	// API. In Local mode, this client dials the configured unix socket.
	// Callers must not mutate the returned client; it is shared and owned
	// by the Transport.
	AdminClient() *http.Client

	// Close releases any long-lived resources held by the Transport
	// (idle HTTP connections, overlay sockets, etc.). Close must be
	// idempotent: calling it more than once returns nil on subsequent
	// calls.
	Close() error
}
