// Package transport abstracts the edge<->hub reachability layer described in
// the P1 core gateway design.
//
// A Transport exposes two primitives:
//
//   - DialSOCKS(ctx, port) — returns a net.Conn to a SOCKS5 endpoint on the
//     hub's Tor pool. In local mode this is a plain TCP loopback dial; in the
//     wave 2 remote transports it will traverse a WireGuard overlay, a
//     WebSocket-over-HTTPS tunnel, or a SOCKS5-over-TLS stream.
//
//   - AdminClient() — returns an *http.Client that reaches the hub admin
//     HTTP API. In local mode, the client dials a unix socket; in remote
//     modes it targets the wg-private admin listener or the mTLS HTTPS
//     endpoint.
//
// The interface is deliberately narrow: everything the proxy pipeline needs
// from the hub goes through these two methods, so adding a new transport
// kind is a matter of implementing the interface once and selecting it at
// bootstrap. Runtime transport switching is explicitly out of scope —
// transport is infrastructure, not runtime state.
//
// Wave 1 ships only the Local implementation, which is drop-in compatible
// with the existing unix-socket torpool admin API and the 127.0.0.1 SOCKS5
// port layout used by internal/proxy. The Wireguard, HTTPSTunnel, and
// SOCKS5TLS implementations arrive in wave 2.
//
// # SOCKS5-over-TLS wire format
//
// The SOCKS5TLS transport fronts the hub's per-instance Tor SOCKS5 ports
// behind a single TLS+mTLS listener. Because a single TCP/TLS endpoint
// cannot infer which underlying SOCKS5 port the edge wants, the edge
// announces the target port to the hub with a 2-byte big-endian uint16
// preamble sent before any SOCKS5 bytes:
//
//	+--------+--------+-------------------------+
//	| port_hi| port_lo| raw SOCKS5 client bytes |
//	+--------+--------+-------------------------+
//	   1 B      1 B            N bytes
//
// The hub's unwrapper reads exactly two bytes, interprets them as a
// big-endian uint16 port number P, then forwards the remainder of the
// stream verbatim to 127.0.0.1:P on its loopback interface. The caller on
// the edge side only needs to emit the two port bytes once, immediately
// after the TLS handshake completes; everything after that is ordinary
// SOCKS5 and is passed through bi-directionally by the hub.
//
// This framing is deliberately minimal: it fits inside the first write
// alongside the SOCKS5 greeting so that a well-behaved client only incurs
// a single userspace->TLS flush. The preamble is not authenticated or
// length-framed — the enclosing TLS+mTLS already provides confidentiality,
// integrity, and peer authentication, so adding an extra MAC here would be
// redundant overhead.
package transport
