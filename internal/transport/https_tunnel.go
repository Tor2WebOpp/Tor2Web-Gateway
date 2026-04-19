package transport

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// Default values for HTTPSTunnelConfig. Exposed so callers and tests can
// reason about timings without inspecting defaults applied in
// NewHTTPSTunnel.
const (
	defaultHTTPSTunnelDialTimeout   = 10 * time.Second
	defaultHTTPSTunnelClientTimeout = 30 * time.Second
)

// HTTPSTunnelConfig parameterises the HTTPS-tunnel Transport. The three
// file paths are required; the timeouts fall back to defaults when zero.
type HTTPSTunnelConfig struct {
	// HubURL is the hub's base URL, e.g. "https://hub.example:8443".
	// Must parse as an absolute URL with an https scheme.
	HubURL string

	// CACertFile is a PEM file containing the CA that signed the hub's
	// server certificate. Used as the sole RootCA when verifying the
	// server.
	CACertFile string

	// ClientCertFile / ClientKeyFile together form the mTLS client
	// identity presented to the hub. Must be a matching PEM pair.
	ClientCertFile string
	ClientKeyFile  string

	// DialTimeout bounds each TLS dial attempt (TCP connect + TLS
	// handshake). Defaults to 10s when zero.
	DialTimeout time.Duration

	// ClientTimeout is the overall request timeout applied to the
	// AdminClient *http.Client. Defaults to 30s when zero.
	ClientTimeout time.Duration
}

// HTTPSTunnel is the remote-mode Transport that multiplexes SOCKS5 streams
// and the admin HTTP API over a single mTLS-protected HTTPS endpoint on
// the hub.
//
// DialSOCKS speaks HTTP/1.1 CONNECT to the hub; on a 200 response the
// underlying TLS conn is handed back as a raw bidirectional stream for the
// caller's SOCKS5 client. AdminClient returns an *http.Client configured
// with the same TLS+mTLS settings and targeting the configured HubURL.
type HTTPSTunnel struct {
	cfg HTTPSTunnelConfig

	hubURL    *url.URL
	hubHost   string // host:port for net.Dial
	tlsConfig *tls.Config

	httpClient *http.Client
	httpTrans  *http.Transport

	closed atomic.Bool
}

// NewHTTPSTunnel builds an HTTPSTunnel from cfg. It loads the CA pool and
// client keypair up-front so configuration errors surface before first
// use.
func NewHTTPSTunnel(cfg HTTPSTunnelConfig) (*HTTPSTunnel, error) {
	if cfg.HubURL == "" {
		return nil, errors.New("transport/https_tunnel: HubURL is required")
	}
	if cfg.CACertFile == "" {
		return nil, errors.New("transport/https_tunnel: CACertFile is required")
	}
	if cfg.ClientCertFile == "" {
		return nil, errors.New("transport/https_tunnel: ClientCertFile is required")
	}
	if cfg.ClientKeyFile == "" {
		return nil, errors.New("transport/https_tunnel: ClientKeyFile is required")
	}

	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = defaultHTTPSTunnelDialTimeout
	}
	if cfg.ClientTimeout <= 0 {
		cfg.ClientTimeout = defaultHTTPSTunnelClientTimeout
	}

	hubURL, err := url.Parse(cfg.HubURL)
	if err != nil {
		return nil, fmt.Errorf("transport/https_tunnel: parse HubURL %q: %w", cfg.HubURL, err)
	}
	if hubURL.Scheme != "https" {
		return nil, fmt.Errorf("transport/https_tunnel: HubURL scheme must be https, got %q", hubURL.Scheme)
	}
	if hubURL.Host == "" {
		return nil, fmt.Errorf("transport/https_tunnel: HubURL %q missing host", cfg.HubURL)
	}

	hubHost := hubURL.Host
	if _, _, err := net.SplitHostPort(hubHost); err != nil {
		// Default HTTPS port when not specified.
		hubHost = net.JoinHostPort(hubURL.Hostname(), "443")
	}

	caPEM, err := os.ReadFile(cfg.CACertFile)
	if err != nil {
		return nil, fmt.Errorf("transport/https_tunnel: read CA cert %q: %w", cfg.CACertFile, err)
	}
	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("transport/https_tunnel: CA cert %q contains no usable PEM blocks", cfg.CACertFile)
	}

	clientCert, err := tls.LoadX509KeyPair(cfg.ClientCertFile, cfg.ClientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("transport/https_tunnel: load client keypair: %w", err)
	}

	tlsConfig := &tls.Config{
		RootCAs:      rootCAs,
		Certificates: []tls.Certificate{clientCert},
		ServerName:   hubURL.Hostname(),
		MinVersion:   tls.VersionTLS12,
	}

	httpTrans := &http.Transport{
		TLSClientConfig:       tlsConfig.Clone(),
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   cfg.DialTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   cfg.DialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	httpClient := &http.Client{
		Transport: httpTrans,
		Timeout:   cfg.ClientTimeout,
	}

	return &HTTPSTunnel{
		cfg:        cfg,
		hubURL:     hubURL,
		hubHost:    hubHost,
		tlsConfig:  tlsConfig,
		httpClient: httpClient,
		httpTrans:  httpTrans,
	}, nil
}

// DialSOCKS opens a TLS connection to the hub, sends an HTTP/1.1 CONNECT
// request to /tunnel/socks/<port>, reads the response status line, and —
// on a 200 response — returns the underlying conn as a raw bidirectional
// byte stream for the caller's SOCKS5 client.
//
// Any non-200 response closes the conn and returns an error. ctx is
// honored throughout: cancellation during dial, handshake, or the CONNECT
// round-trip aborts the attempt.
func (h *HTTPSTunnel) DialSOCKS(ctx context.Context, port int) (net.Conn, error) {
	if h.closed.Load() {
		return nil, errors.New("transport/https_tunnel: transport is closed")
	}
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("transport/https_tunnel: dial socks: invalid port %d", port)
	}

	dialer := &net.Dialer{Timeout: h.cfg.DialTimeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", h.hubHost)
	if err != nil {
		return nil, fmt.Errorf("transport/https_tunnel: tcp dial %s: %w", h.hubHost, err)
	}

	tlsConn := tls.Client(rawConn, h.tlsConfig.Clone())

	// Bound the handshake by ctx and DialTimeout.
	hsCtx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		hsCtx, cancel = context.WithTimeout(ctx, h.cfg.DialTimeout)
		defer cancel()
	}
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("transport/https_tunnel: tls handshake %s: %w", h.hubHost, err)
	}

	// Best-effort: propagate ctx cancellation to the CONNECT request by
	// setting a deadline. Guarded: if ctx has no deadline, fall back to
	// DialTimeout.
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(h.cfg.DialTimeout)
	}
	if err := tlsConn.SetDeadline(deadline); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("transport/https_tunnel: set deadline: %w", err)
	}

	// Also react to ctx cancellation that happens mid-write/read by
	// closing the conn from a watcher goroutine. The watcher must exit
	// BEFORE this function returns the conn to the caller — otherwise
	// a ctx that cancels a hair after CONNECT succeeds races the defer
	// and the watcher may close the conn the caller just received.
	// Pattern: stopped chan is closed only by the watcher after it
	// picks a branch; the deferred Wait blocks until the watcher
	// commits to a non-close path.
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		select {
		case <-ctx.Done():
			_ = tlsConn.Close()
		case <-done:
		}
	}()
	defer func() {
		close(done)
		<-stopped
	}()

	req := fmt.Sprintf(
		"CONNECT /tunnel/socks/%d HTTP/1.1\r\nHost: %s\r\n\r\n",
		port, h.hubURL.Host,
	)
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("transport/https_tunnel: write CONNECT: %w", err)
	}

	// Read only the response status line + headers. We use bufio.Reader
	// but buffer it minimally so any bytes that leak past the header
	// boundary (which the hub promises not to send until after 200) are
	// still retrievable — if the peer is well-behaved there are none.
	br := bufio.NewReader(tlsConn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("transport/https_tunnel: read CONNECT status: %w", err)
	}
	statusLine = strings.TrimRight(statusLine, "\r\n")

	// Parse status: "HTTP/1.1 200 Connection established" or similar.
	if !isConnectSuccessStatus(statusLine) {
		// Drain the rest of the headers so logs on the server side
		// don't see a broken pipe before they finish flushing.
		_ = drainHeaders(br)
		_ = tlsConn.Close()
		return nil, fmt.Errorf("transport/https_tunnel: CONNECT rejected: %q", statusLine)
	}

	// Consume header lines up to the blank line terminator.
	if err := drainHeaders(br); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("transport/https_tunnel: read CONNECT headers: %w", err)
	}

	// If the server sent any bytes beyond the header block, they belong
	// to the tunneled stream. Wrap them so the caller sees a seamless
	// Conn.
	if br.Buffered() > 0 {
		buffered, _ := br.Peek(br.Buffered())
		conn := &bufferedConn{Conn: tlsConn, extra: append([]byte(nil), buffered...)}
		// Clear any deadline we set for the handshake; the caller owns
		// deadlines from here on.
		_ = tlsConn.SetDeadline(time.Time{})
		return conn, nil
	}

	_ = tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
}

// AdminClient returns the shared *http.Client whose TLS config matches the
// tunnel's mTLS identity. Callers should issue requests against paths
// under the HubURL (e.g. "/v1/tenants") and must not mutate the client.
func (h *HTTPSTunnel) AdminClient() *http.Client {
	return h.httpClient
}

// Close releases idle HTTP connections held by the admin client. Safe to
// call more than once; subsequent calls are no-ops and return nil.
func (h *HTTPSTunnel) Close() error {
	if h.closed.Swap(true) {
		return nil
	}
	if h.httpTrans != nil {
		h.httpTrans.CloseIdleConnections()
	}
	return nil
}

// HubURL returns the base URL configured for this tunnel. Convenience for
// callers that want to assemble admin request URLs against the tunnel's
// target.
func (h *HTTPSTunnel) HubURL() string {
	return h.cfg.HubURL
}

// isConnectSuccessStatus returns true when line starts with a valid
// HTTP/1.x 200 status. Example matching lines:
//
//	"HTTP/1.1 200 OK"
//	"HTTP/1.0 200 Connection established"
func isConnectSuccessStatus(line string) bool {
	if !strings.HasPrefix(line, "HTTP/1.") {
		return false
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return false
	}
	return parts[1] == "200"
}

// drainHeaders reads from br until an empty line (\r\n or \n) is
// encountered, representing the end of the HTTP header block. Returns
// nil on success or the underlying read error.
func drainHeaders(br *bufio.Reader) error {
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return err
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			return nil
		}
	}
}

// bufferedConn wraps a net.Conn and prepends a byte slice to its Read
// stream. Used by DialSOCKS when the peer sends data past the CONNECT
// header terminator; those bytes must be re-fed to the caller before the
// underlying conn is read from directly.
type bufferedConn struct {
	net.Conn
	extra []byte
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	if len(b.extra) > 0 {
		n := copy(p, b.extra)
		b.extra = b.extra[n:]
		return n, nil
	}
	return b.Conn.Read(p)
}

// Compile-time assertion that *HTTPSTunnel satisfies Transport.
var _ Transport = (*HTTPSTunnel)(nil)
