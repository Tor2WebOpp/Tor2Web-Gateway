package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

// Default values for SOCKS5TLSConfig. Mirrored by NewSOCKS5TLS when the
// caller leaves the corresponding field zero.
const (
	defaultSOCKS5TLSDialTimeout   = 5 * time.Second
	defaultSOCKS5TLSClientTimeout = 10 * time.Second
)

// SOCKS5TLSConfig parameterises the SOCKS5-over-TLS transport. HubAddr and
// AdminAddr are the two public-facing TLS endpoints on the hub; the three
// file paths describe the mTLS identity used to reach them. The timeout
// fields fall back to defaults when zero.
type SOCKS5TLSConfig struct {
	// HubAddr is the host:port of the hub's SOCKS5-TLS listener. The
	// listener demultiplexes to the torpool's per-instance SOCKS ports by
	// reading the 2-byte big-endian port preamble documented in the
	// package overview.
	HubAddr string

	// AdminAddr is the host:port of the hub's mTLS admin HTTPS endpoint.
	AdminAddr string

	// CACertFile is a PEM file containing one or more root CAs that sign
	// the hub's server certificate. Required.
	CACertFile string

	// ClientCertFile is a PEM-encoded X.509 certificate presented to the
	// hub for mTLS. Required.
	ClientCertFile string

	// ClientKeyFile is the PEM-encoded private key paired with
	// ClientCertFile. Required.
	ClientKeyFile string

	// DialTimeout bounds each TCP+TLS dial attempt for both SOCKS and
	// admin connections. Defaults to 5s when zero.
	DialTimeout time.Duration

	// ClientTimeout is the overall request timeout applied to the
	// AdminClient *http.Client. Defaults to 10s when zero.
	ClientTimeout time.Duration
}

// SOCKS5TLS is the wave 2 Transport implementation that fronts the hub's
// Tor pool behind a single TLS+mTLS listener. The same tls.Config — with
// the hub CA pinned and the edge's client cert loaded — is shared between
// DialSOCKS and the AdminClient so that certificate rotation touches one
// code path.
type SOCKS5TLS struct {
	cfg       SOCKS5TLSConfig
	tlsConfig *tls.Config

	httpClient *http.Client
	transport  *http.Transport

	closed atomic.Bool
}

// NewSOCKS5TLS loads the CA, the client certificate, and the client key,
// constructs the shared tls.Config, and returns a ready-to-use transport.
// All three file paths must resolve to readable PEM files; any load
// failure is reported as a wrapped error so operators can see which file
// was the culprit.
func NewSOCKS5TLS(cfg SOCKS5TLSConfig) (*SOCKS5TLS, error) {
	if cfg.HubAddr == "" {
		return nil, errors.New("transport/socks5tls: hub_addr is required")
	}
	if cfg.AdminAddr == "" {
		return nil, errors.New("transport/socks5tls: admin_addr is required")
	}
	if cfg.CACertFile == "" {
		return nil, errors.New("transport/socks5tls: ca_cert_file is required")
	}
	if cfg.ClientCertFile == "" {
		return nil, errors.New("transport/socks5tls: client_cert_file is required")
	}
	if cfg.ClientKeyFile == "" {
		return nil, errors.New("transport/socks5tls: client_key_file is required")
	}

	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = defaultSOCKS5TLSDialTimeout
	}
	if cfg.ClientTimeout <= 0 {
		cfg.ClientTimeout = defaultSOCKS5TLSClientTimeout
	}

	caPEM, err := os.ReadFile(cfg.CACertFile)
	if err != nil {
		return nil, fmt.Errorf("transport/socks5tls: read ca %q: %w", cfg.CACertFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("transport/socks5tls: ca_cert_file %q contains no valid certificates", cfg.CACertFile)
	}

	clientCert, err := tls.LoadX509KeyPair(cfg.ClientCertFile, cfg.ClientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("transport/socks5tls: load client keypair: %w", err)
	}

	// ServerName is intentionally left empty; the dial path fills it per
	// connection so the same tls.Config works for both HubAddr and
	// AdminAddr without requiring a shared SAN between them.
	tlsConfig := &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{clientCert},
		MinVersion:   tls.VersionTLS12,
	}

	st := &SOCKS5TLS{
		cfg:       cfg,
		tlsConfig: tlsConfig,
	}

	// Build a dedicated *http.Transport for the admin client. The
	// DialTLSContext callback reuses the shared tlsConfig so that cert
	// rotation in future waves is a single-point swap.
	st.transport = &http.Transport{
		DialTLSContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			// http.Transport resolves Request.URL.Host into addr; we
			// substitute the configured AdminAddr so that callers can
			// use any placeholder host in the request URL.
			_ = addr
			return st.dialTLS(ctx, cfg.AdminAddr)
		},
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        8,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
	}
	st.httpClient = &http.Client{
		Transport: st.transport,
		Timeout:   cfg.ClientTimeout,
	}

	return st, nil
}

// dialTLS performs a TCP+TLS dial to addr using the transport's shared
// tls.Config. The hostname portion of addr is used as the SNI/ServerName
// so that hubs running multiple virtual endpoints behind the same IP still
// present the correct certificate.
func (s *SOCKS5TLS) dialTLS(ctx context.Context, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("transport/socks5tls: split host/port %q: %w", addr, err)
	}

	dialer := &net.Dialer{Timeout: s.cfg.DialTimeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("transport/socks5tls: dial %s: %w", addr, err)
	}

	// Clone the shared config so we can set ServerName without racing
	// against other in-flight dials sharing the same *tls.Config.
	tlsCfg := s.tlsConfig.Clone()
	tlsCfg.ServerName = host

	tlsConn := tls.Client(rawConn, tlsCfg)
	// Honor ctx during the handshake by wiring it through
	// HandshakeContext. On success the returned net.Conn is the
	// *tls.Conn; on failure the raw TCP leg is closed first.
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("transport/socks5tls: tls handshake %s: %w", addr, err)
	}
	return tlsConn, nil
}

// DialSOCKS opens a TLS+mTLS connection to HubAddr, writes the 2-byte
// big-endian uint16 port preamble documented in doc.go, and returns the
// resulting net.Conn. The caller then speaks raw SOCKS5 over the returned
// connection; the hub's unwrapper reads the preamble and bridges to the
// matching loopback SOCKS5 port on its own torpool.
//
// Port validation: only 1..65535 is accepted. Zero and negative values
// return an error before any network I/O.
func (s *SOCKS5TLS) DialSOCKS(ctx context.Context, port int) (net.Conn, error) {
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("transport/socks5tls: dial socks: invalid port %d", port)
	}

	conn, err := s.dialTLS(ctx, s.cfg.HubAddr)
	if err != nil {
		return nil, err
	}

	// Apply the dial deadline to the preamble write as well so a stuck
	// hub unwrapper cannot pin a goroutine forever.
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(dl)
	} else {
		_ = conn.SetWriteDeadline(time.Now().Add(s.cfg.DialTimeout))
	}

	var preamble [2]byte
	binary.BigEndian.PutUint16(preamble[:], uint16(port))
	if _, err := conn.Write(preamble[:]); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("transport/socks5tls: write port preamble: %w", err)
	}

	// Clear the write deadline so downstream SOCKS5 traffic runs under
	// the caller's own deadline regime.
	_ = conn.SetWriteDeadline(time.Time{})
	return conn, nil
}

// AdminClient returns the shared *http.Client that dials AdminAddr over
// TLS+mTLS. The returned client is safe for concurrent use but must not
// be mutated by callers.
func (s *SOCKS5TLS) AdminClient() *http.Client {
	return s.httpClient
}

// Close closes idle connections on the admin client's http.Transport.
// Safe to call more than once; subsequent calls are no-ops and return nil.
func (s *SOCKS5TLS) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	if s.transport != nil {
		s.transport.CloseIdleConnections()
	}
	return nil
}

// Compile-time assertion that *SOCKS5TLS satisfies Transport.
var _ Transport = (*SOCKS5TLS)(nil)
