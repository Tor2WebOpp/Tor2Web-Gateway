package transport

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// tunnelPKI holds the PEM-encoded file paths for a self-signed CA and the
// signed server + client certificates it produces. All files live under
// t.TempDir() and are cleaned up automatically.
type tunnelPKI struct {
	CAFile         string
	ServerCertFile string
	ServerKeyFile  string
	ClientCertFile string
	ClientKeyFile  string

	ServerCert tls.Certificate
	CAPool     *x509.CertPool
}

func newTunnelPKI(t *testing.T) *tunnelPKI {
	t.Helper()
	dir := t.TempDir()

	// --- Self-signed CA ------------------------------------------------
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-gateway-ca"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:         true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	caFile := filepath.Join(dir, "ca.pem")
	writePEM(t, caFile, "CERTIFICATE", caDER)

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	// --- Server cert (CN=localhost, SAN DNS/IP) -----------------------
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("server key: %v", err)
	}
	serverTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTpl, caTpl, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("server cert: %v", err)
	}
	serverCertFile := filepath.Join(dir, "server.crt")
	serverKeyFile := filepath.Join(dir, "server.key")
	writePEM(t, serverCertFile, "CERTIFICATE", serverDER)
	writeECKey(t, serverKeyFile, serverKey)

	serverTLSCert, err := tls.LoadX509KeyPair(serverCertFile, serverKeyFile)
	if err != nil {
		t.Fatalf("load server cert: %v", err)
	}

	// --- Client cert (CN=test-edge) -----------------------------------
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	clientTpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "test-edge"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTpl, caTpl, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("client cert: %v", err)
	}
	clientCertFile := filepath.Join(dir, "client.crt")
	clientKeyFile := filepath.Join(dir, "client.key")
	writePEM(t, clientCertFile, "CERTIFICATE", clientDER)
	writeECKey(t, clientKeyFile, clientKey)

	return &tunnelPKI{
		CAFile:         caFile,
		ServerCertFile: serverCertFile,
		ServerKeyFile:  serverKeyFile,
		ClientCertFile: clientCertFile,
		ClientKeyFile:  clientKeyFile,
		ServerCert:     serverTLSCert,
		CAPool:         caPool,
	}
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %q: %v", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		t.Fatalf("pem encode: %v", err)
	}
}

func writeECKey(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal ec key: %v", err)
	}
	writePEM(t, path, "EC PRIVATE KEY", der)
}

// startTunnelServer spins up a TLS server that requires mTLS with pki and
// dispatches on method: CONNECT requests run connectHandler with the raw
// TLS conn; other requests run httpHandler as a regular HTTP server.
//
// When connectHandler is nil, CONNECT requests receive 403 Forbidden.
// When httpHandler is nil, non-CONNECT requests receive 404 Not Found.
func startTunnelServer(
	t *testing.T,
	pki *tunnelPKI,
	connectHandler func(t *testing.T, req string, conn net.Conn),
	httpHandler http.Handler,
) (addr string, closeFn func()) {
	t.Helper()

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{pki.ServerCert},
		ClientCAs:    pki.CAPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-stop:
					return
				default:
				}
				// Benign if we've been asked to stop; otherwise log.
				if !errors.Is(err, net.ErrClosed) {
					t.Logf("accept: %v", err)
				}
				return
			}

			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				handleTunnelConn(t, c, connectHandler, httpHandler)
			}(conn)
		}
	}()

	closeFn = func() {
		close(stop)
		_ = ln.Close()
		wg.Wait()
	}

	return ln.Addr().String(), closeFn
}

// handleTunnelConn peeks the first request line to distinguish CONNECT
// from other methods, then dispatches.
func handleTunnelConn(
	t *testing.T,
	conn net.Conn,
	connectHandler func(t *testing.T, req string, conn net.Conn),
	httpHandler http.Handler,
) {
	t.Helper()

	// Ensure TLS handshake completes so client-cert verification
	// failures are surfaced here rather than mid-HTTP.
	if tc, ok := conn.(*tls.Conn); ok {
		if err := tc.Handshake(); err != nil {
			_ = conn.Close()
			return
		}
	}

	br := bufio.NewReader(conn)
	requestLine, err := br.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return
	}

	// Drain header block.
	var headerBuf []byte
	headerBuf = append(headerBuf, requestLine...)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			_ = conn.Close()
			return
		}
		headerBuf = append(headerBuf, line...)
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	if len(requestLine) >= 7 && requestLine[:7] == "CONNECT" {
		if connectHandler == nil {
			_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"))
			_ = conn.Close()
			return
		}
		connectHandler(t, string(headerBuf), conn)
		return
	}

	// Re-serve the already-consumed bytes by wrapping the conn.
	replay := &prefixConn{Conn: conn, extra: headerBuf}
	listener := &oneShotListener{conn: replay}

	srv := &http.Server{Handler: httpHandler}
	if httpHandler == nil {
		srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		})
	}
	_ = srv.Serve(listener)
}

// prefixConn prepends a byte slice to the Read stream of its wrapped conn.
type prefixConn struct {
	net.Conn
	extra []byte
}

func (p *prefixConn) Read(b []byte) (int, error) {
	if len(p.extra) > 0 {
		n := copy(b, p.extra)
		p.extra = p.extra[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

// oneShotListener yields a single pre-accepted conn, then blocks on Accept
// (returning an error once closed). Used to serve one HTTP request over
// an already-handshaken TLS conn.
type oneShotListener struct {
	conn net.Conn
	once sync.Once
	done chan struct{}
}

func (o *oneShotListener) Accept() (net.Conn, error) {
	var ret net.Conn
	var err error = errors.New("oneShotListener: no more conns")

	o.once.Do(func() {
		ret = o.conn
		err = nil
		o.done = make(chan struct{})
	})
	if ret != nil {
		return ret, nil
	}
	if o.done != nil {
		<-o.done
	}
	return nil, err
}

func (o *oneShotListener) Close() error {
	if o.done != nil {
		select {
		case <-o.done:
		default:
			close(o.done)
		}
	}
	return nil
}

func (o *oneShotListener) Addr() net.Addr {
	return o.conn.LocalAddr()
}

// --- Tests ---------------------------------------------------------------

func TestNewHTTPSTunnel_Validation(t *testing.T) {
	pki := newTunnelPKI(t)

	cases := []struct {
		name string
		mut  func(*HTTPSTunnelConfig)
	}{
		{"empty HubURL", func(c *HTTPSTunnelConfig) { c.HubURL = "" }},
		{"empty CA", func(c *HTTPSTunnelConfig) { c.CACertFile = "" }},
		{"empty client cert", func(c *HTTPSTunnelConfig) { c.ClientCertFile = "" }},
		{"empty client key", func(c *HTTPSTunnelConfig) { c.ClientKeyFile = "" }},
		{"http scheme", func(c *HTTPSTunnelConfig) { c.HubURL = "http://hub:8443" }},
		{"unparseable URL", func(c *HTTPSTunnelConfig) { c.HubURL = "://bad" }},
		{"missing CA file", func(c *HTTPSTunnelConfig) { c.CACertFile = filepath.Join(t.TempDir(), "nope") }},
		{"missing client cert", func(c *HTTPSTunnelConfig) { c.ClientCertFile = filepath.Join(t.TempDir(), "nope") }},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg := HTTPSTunnelConfig{
				HubURL:         "https://hub.example:8443",
				CACertFile:     pki.CAFile,
				ClientCertFile: pki.ClientCertFile,
				ClientKeyFile:  pki.ClientKeyFile,
			}
			tc.mut(&cfg)
			if _, err := NewHTTPSTunnel(cfg); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestNewHTTPSTunnel_Defaults(t *testing.T) {
	pki := newTunnelPKI(t)
	tun, err := NewHTTPSTunnel(HTTPSTunnelConfig{
		HubURL:         "https://hub.example:8443",
		CACertFile:     pki.CAFile,
		ClientCertFile: pki.ClientCertFile,
		ClientKeyFile:  pki.ClientKeyFile,
	})
	if err != nil {
		t.Fatalf("NewHTTPSTunnel: %v", err)
	}
	t.Cleanup(func() { _ = tun.Close() })

	if tun.cfg.DialTimeout != defaultHTTPSTunnelDialTimeout {
		t.Errorf("DialTimeout = %s, want %s", tun.cfg.DialTimeout, defaultHTTPSTunnelDialTimeout)
	}
	if tun.cfg.ClientTimeout != defaultHTTPSTunnelClientTimeout {
		t.Errorf("ClientTimeout = %s, want %s", tun.cfg.ClientTimeout, defaultHTTPSTunnelClientTimeout)
	}
	if tun.httpClient == nil {
		t.Error("httpClient is nil")
	}
	if tun.httpClient.Timeout != defaultHTTPSTunnelClientTimeout {
		t.Errorf("httpClient.Timeout = %s, want %s", tun.httpClient.Timeout, defaultHTTPSTunnelClientTimeout)
	}
	if tun.tlsConfig == nil {
		t.Error("tlsConfig is nil")
	}
	if tun.tlsConfig.ServerName != "hub.example" {
		t.Errorf("ServerName = %q, want %q", tun.tlsConfig.ServerName, "hub.example")
	}
	if got := len(tun.tlsConfig.Certificates); got != 1 {
		t.Errorf("Certificates len = %d, want 1", got)
	}
	if tun.tlsConfig.RootCAs == nil {
		t.Error("RootCAs is nil")
	}
}

func TestHTTPSTunnel_DialSOCKS_EndToEnd(t *testing.T) {
	pki := newTunnelPKI(t)

	// Backend that echoes whatever bytes it receives, for round-trip
	// verification. Runs in-memory via net.Pipe.
	clientSide, backendSide := net.Pipe()
	backendDone := make(chan struct{})
	go func() {
		defer close(backendDone)
		defer backendSide.Close()
		buf := make([]byte, 64)
		for {
			n, err := backendSide.Read(buf)
			if err != nil {
				return
			}
			if _, err := backendSide.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	connectHandler := func(t *testing.T, req string, conn net.Conn) {
		if _, err := conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
			t.Logf("write 200: %v", err)
			_ = conn.Close()
			return
		}
		// Bidirectionally proxy conn <-> clientSide.
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = io.Copy(clientSide, conn)
			_ = clientSide.Close()
		}()
		go func() {
			defer wg.Done()
			_, _ = io.Copy(conn, clientSide)
			_ = conn.Close()
		}()
		wg.Wait()
	}

	addr, stop := startTunnelServer(t, pki, connectHandler, nil)
	t.Cleanup(stop)

	tun, err := NewHTTPSTunnel(HTTPSTunnelConfig{
		HubURL:         "https://" + addr,
		CACertFile:     pki.CAFile,
		ClientCertFile: pki.ClientCertFile,
		ClientKeyFile:  pki.ClientKeyFile,
		DialTimeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewHTTPSTunnel: %v", err)
	}
	t.Cleanup(func() { _ = tun.Close() })

	// Override ServerName to match our cert's SAN (localhost).
	tun.tlsConfig.ServerName = "localhost"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := tun.DialSOCKS(ctx, 9050)
	if err != nil {
		t.Fatalf("DialSOCKS: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello-tunnel")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	buf := make([]byte, len(payload))
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("echo mismatch: got %q want %q", string(buf), string(payload))
	}

	_ = conn.Close()
	<-backendDone
}

func TestHTTPSTunnel_DialSOCKS_Forbidden(t *testing.T) {
	pki := newTunnelPKI(t)

	connectHandler := func(t *testing.T, req string, conn net.Conn) {
		_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"))
		_ = conn.Close()
	}

	addr, stop := startTunnelServer(t, pki, connectHandler, nil)
	t.Cleanup(stop)

	tun, err := NewHTTPSTunnel(HTTPSTunnelConfig{
		HubURL:         "https://" + addr,
		CACertFile:     pki.CAFile,
		ClientCertFile: pki.ClientCertFile,
		ClientKeyFile:  pki.ClientKeyFile,
	})
	if err != nil {
		t.Fatalf("NewHTTPSTunnel: %v", err)
	}
	t.Cleanup(func() { _ = tun.Close() })
	tun.tlsConfig.ServerName = "localhost"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := tun.DialSOCKS(ctx, 9050)
	if err == nil {
		_ = conn.Close()
		t.Fatal("DialSOCKS returned nil error on 403 response")
	}
}

func TestHTTPSTunnel_DialSOCKS_RejectsInvalidPort(t *testing.T) {
	pki := newTunnelPKI(t)
	tun, err := NewHTTPSTunnel(HTTPSTunnelConfig{
		HubURL:         "https://hub.example:8443",
		CACertFile:     pki.CAFile,
		ClientCertFile: pki.ClientCertFile,
		ClientKeyFile:  pki.ClientKeyFile,
	})
	if err != nil {
		t.Fatalf("NewHTTPSTunnel: %v", err)
	}
	t.Cleanup(func() { _ = tun.Close() })

	for _, p := range []int{0, -1, 65536} {
		if _, err := tun.DialSOCKS(context.Background(), p); err == nil {
			t.Errorf("port=%d: expected error, got nil", p)
		}
	}
}

func TestHTTPSTunnel_AdminClient_GET(t *testing.T) {
	pki := newTunnelPKI(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/tenants", func(w http.ResponseWriter, r *http.Request) {
		// Confirm that client cert was presented.
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "no client cert", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"tenants":[]}`)
	})

	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{pki.ServerCert},
		ClientCAs:    pki.CAPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse srv url: %v", err)
	}

	tun, err := NewHTTPSTunnel(HTTPSTunnelConfig{
		HubURL:         srv.URL,
		CACertFile:     pki.CAFile,
		ClientCertFile: pki.ClientCertFile,
		ClientKeyFile:  pki.ClientKeyFile,
	})
	if err != nil {
		t.Fatalf("NewHTTPSTunnel: %v", err)
	}
	t.Cleanup(func() { _ = tun.Close() })

	// httptest uses 127.0.0.1 as the server name; our cert SANs include
	// that IP, so no ServerName override is needed — but be explicit.
	if host := u.Hostname(); host != "" {
		tun.httpTrans.TLSClientConfig.ServerName = host
	}

	client := tun.AdminClient()
	if client == nil {
		t.Fatal("AdminClient returned nil")
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/v1/tenants", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if got := string(body); got != `{"tenants":[]}` {
		t.Fatalf("body = %q, want %q", got, `{"tenants":[]}`)
	}
}

func TestHTTPSTunnel_AdminClient_SharedInstance(t *testing.T) {
	pki := newTunnelPKI(t)
	tun, err := NewHTTPSTunnel(HTTPSTunnelConfig{
		HubURL:         "https://hub.example:8443",
		CACertFile:     pki.CAFile,
		ClientCertFile: pki.ClientCertFile,
		ClientKeyFile:  pki.ClientKeyFile,
	})
	if err != nil {
		t.Fatalf("NewHTTPSTunnel: %v", err)
	}
	t.Cleanup(func() { _ = tun.Close() })

	a := tun.AdminClient()
	b := tun.AdminClient()
	if a == nil || b == nil {
		t.Fatal("AdminClient returned nil")
	}
	if a != b {
		t.Fatalf("AdminClient returned distinct clients: %p vs %p", a, b)
	}
}

func TestHTTPSTunnel_Close_Idempotent(t *testing.T) {
	pki := newTunnelPKI(t)
	tun, err := NewHTTPSTunnel(HTTPSTunnelConfig{
		HubURL:         "https://hub.example:8443",
		CACertFile:     pki.CAFile,
		ClientCertFile: pki.ClientCertFile,
		ClientKeyFile:  pki.ClientKeyFile,
	})
	if err != nil {
		t.Fatalf("NewHTTPSTunnel: %v", err)
	}

	if err := tun.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := tun.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := tun.Close(); err != nil {
		t.Fatalf("third Close: %v", err)
	}

	// Dialing after close must fail immediately without attempting TCP.
	_, err = tun.DialSOCKS(context.Background(), 9050)
	if err == nil {
		t.Fatal("DialSOCKS after Close returned nil error")
	}
}

func TestHTTPSTunnel_InterfaceSatisfied(t *testing.T) {
	var _ Transport = (*HTTPSTunnel)(nil)

	pki := newTunnelPKI(t)
	var tr Transport
	tun, err := NewHTTPSTunnel(HTTPSTunnelConfig{
		HubURL:         "https://hub.example:8443",
		CACertFile:     pki.CAFile,
		ClientCertFile: pki.ClientCertFile,
		ClientKeyFile:  pki.ClientKeyFile,
	})
	if err != nil {
		t.Fatalf("NewHTTPSTunnel: %v", err)
	}
	tr = tun
	t.Cleanup(func() { _ = tr.Close() })

	if tr.AdminClient() == nil {
		t.Fatal("AdminClient returned nil")
	}
}

func TestHTTPSTunnel_HubURL(t *testing.T) {
	pki := newTunnelPKI(t)
	tun, err := NewHTTPSTunnel(HTTPSTunnelConfig{
		HubURL:         "https://hub.example:8443",
		CACertFile:     pki.CAFile,
		ClientCertFile: pki.ClientCertFile,
		ClientKeyFile:  pki.ClientKeyFile,
	})
	if err != nil {
		t.Fatalf("NewHTTPSTunnel: %v", err)
	}
	t.Cleanup(func() { _ = tun.Close() })

	if got := tun.HubURL(); got != "https://hub.example:8443" {
		t.Fatalf("HubURL() = %q", got)
	}
}

func TestIsConnectSuccessStatus(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"HTTP/1.1 200 OK", true},
		{"HTTP/1.1 200 Connection established", true},
		{"HTTP/1.0 200 OK", true},
		{"HTTP/1.1 403 Forbidden", false},
		{"HTTP/1.1 500 Internal Server Error", false},
		{"HTTP/2 200", false}, // only HTTP/1.x supported
		{"garbage", false},
		{"", false},
		{"HTTP/1.1", false},
	}
	for _, tc := range cases {
		if got := isConnectSuccessStatus(tc.line); got != tc.want {
			t.Errorf("isConnectSuccessStatus(%q) = %v, want %v", tc.line, got, tc.want)
		}
	}
}

func TestDrainHeaders(t *testing.T) {
	input := "X-Foo: bar\r\nContent-Length: 0\r\n\r\nEXTRA"
	br := bufio.NewReader(newStringReader(input))
	if err := drainHeaders(br); err != nil {
		t.Fatalf("drainHeaders: %v", err)
	}
	rest, _ := io.ReadAll(br)
	if string(rest) != "EXTRA" {
		t.Fatalf("remaining bytes = %q, want %q", string(rest), "EXTRA")
	}
}

// newStringReader wraps a string in an io.Reader suitable for
// bufio.NewReader. Exists so the test doesn't pull in strings.Reader by
// reference across files.
func newStringReader(s string) io.Reader {
	return &sReader{s: s}
}

type sReader struct {
	s string
	i int
}

func (r *sReader) Read(p []byte) (int, error) {
	if r.i >= len(r.s) {
		return 0, io.EOF
	}
	n := copy(p, r.s[r.i:])
	r.i += n
	return n, nil
}

// Sanity check: ensure our helper stub for fmt (used by other tests) is
// still referenced so the import graph doesn't drift. Also forces the
// error path of tunnel server setup to not break silently.
func TestTunnelPKI_Sanity(t *testing.T) {
	pki := newTunnelPKI(t)
	if pki.CAFile == "" || pki.ServerCertFile == "" || pki.ClientCertFile == "" {
		t.Fatal("pki paths empty")
	}
	if _, err := os.Stat(pki.CAFile); err != nil {
		t.Fatalf("stat CA: %v", err)
	}
	if _, err := tls.LoadX509KeyPair(pki.ClientCertFile, pki.ClientKeyFile); err != nil {
		t.Fatalf("load client pair: %v", err)
	}
	// Silence unused-import warning for fmt if tests ever drop it.
	_ = fmt.Sprintf
}
