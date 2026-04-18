package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// pkiBundle holds the filesystem paths of a synthetic mini-PKI suitable
// for exercising the SOCKS5TLS transport: one CA, one server leaf, and
// one client leaf — all ECDSA P-256, all signed by the same root.
type pkiBundle struct {
	CACertFile     string
	ServerCert     tls.Certificate
	ClientCertFile string
	ClientKeyFile  string
	CAPool         *x509.CertPool
}

// buildTestPKI mints a self-signed CA and issues server+client leaves
// under it. All keys are ECDSA P-256 because it is fast, deterministic in
// test cost, and requires no special build tags.
//
// The server leaf's SAN includes "localhost" and 127.0.0.1 so both the
// hostname and loopback IP paths validate out of the box.
func buildTestPKI(t *testing.T) *pkiBundle {
	t.Helper()

	dir := t.TempDir()

	// --- CA ---
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("sign ca: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	caCertPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caCertPath, caPEM, 0o600); err != nil {
		t.Fatalf("write ca pem: %v", err)
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	// --- Server leaf ---
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	serverTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTmpl, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("sign server: %v", err)
	}
	serverCert := tls.Certificate{
		Certificate: [][]byte{serverDER},
		PrivateKey:  serverKey,
	}

	// --- Client leaf ---
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	clientTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTmpl, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("sign client: %v", err)
	}

	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})
	clientKeyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyDER})

	clientCertPath := filepath.Join(dir, "client.crt")
	clientKeyPath := filepath.Join(dir, "client.key")
	if err := os.WriteFile(clientCertPath, clientCertPEM, 0o600); err != nil {
		t.Fatalf("write client cert: %v", err)
	}
	if err := os.WriteFile(clientKeyPath, clientKeyPEM, 0o600); err != nil {
		t.Fatalf("write client key: %v", err)
	}

	return &pkiBundle{
		CACertFile:     caCertPath,
		ServerCert:     serverCert,
		ClientCertFile: clientCertPath,
		ClientKeyFile:  clientKeyPath,
		CAPool:         caPool,
	}
}

// startTLSEcho spins up a TLS+mTLS listener on 127.0.0.1:0 that, per
// accepted connection, reads exactly two bytes (the port preamble), sends
// them to portCh, then echoes every subsequent byte back to the client
// until EOF or the test tears the server down.
func startTLSEcho(t *testing.T, pki *pkiBundle) (addr string, portCh <-chan uint16, stop func()) {
	t.Helper()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{pki.ServerCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pki.CAPool,
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}

	ch := make(chan uint16, 4)
	var wg sync.WaitGroup
	done := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
				}
				if errors.Is(err, net.ErrClosed) {
					return
				}
				t.Logf("tls accept: %v", err)
				return
			}
			wg.Add(1)
			go func(conn net.Conn) {
				defer wg.Done()
				defer conn.Close()

				var pre [2]byte
				if _, err := io.ReadFull(conn, pre[:]); err != nil {
					t.Logf("read preamble: %v", err)
					return
				}
				ch <- binary.BigEndian.Uint16(pre[:])

				// Echo until EOF.
				buf := make([]byte, 1024)
				for {
					n, err := conn.Read(buf)
					if n > 0 {
						if _, werr := conn.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()

	stop = func() {
		close(done)
		_ = ln.Close()
		wg.Wait()
	}
	return ln.Addr().String(), ch, stop
}

// startTLSAdmin spins up a TLS+mTLS HTTPS server that serves /ping -> 200
// "pong". Used to verify AdminClient() works end-to-end.
func startTLSAdmin(t *testing.T, pki *pkiBundle) (addr string, stop func()) {
	t.Helper()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{pki.ServerCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pki.CAPool,
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("tls.Listen admin: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "pong")
	})

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Logf("admin srv.Serve: %v", err)
		}
	}()

	stop = func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		<-done
	}
	return ln.Addr().String(), stop
}

func TestSOCKS5TLS_DialSOCKS_WritesPortPreambleAndPassesBytes(t *testing.T) {
	pki := buildTestPKI(t)

	hubAddr, portCh, stopEcho := startTLSEcho(t, pki)
	defer stopEcho()

	tr, err := NewSOCKS5TLS(SOCKS5TLSConfig{
		HubAddr:        hubAddr,
		AdminAddr:      hubAddr, // unused here but required
		CACertFile:     pki.CACertFile,
		ClientCertFile: pki.ClientCertFile,
		ClientKeyFile:  pki.ClientKeyFile,
		DialTimeout:    3 * time.Second,
		ClientTimeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewSOCKS5TLS: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	const targetPort = 9057
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := tr.DialSOCKS(ctx, targetPort)
	if err != nil {
		t.Fatalf("DialSOCKS: %v", err)
	}
	defer conn.Close()

	// Verify the server saw the correct port.
	select {
	case got := <-portCh:
		if got != uint16(targetPort) {
			t.Fatalf("server read port=%d, want %d", got, targetPort)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not receive port preamble within 3s")
	}

	// Now exchange payload bytes and make sure the server echoes them
	// back unchanged (proves the post-preamble stream is clean SOCKS5
	// passthrough, framing-wise).
	payload := []byte("\x05\x01\x00") // classic SOCKS5 greeting bytes
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	got := make([]byte, len(payload))
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo = %x, want %x", got, payload)
	}
}

func TestSOCKS5TLS_DialSOCKS_RejectsInvalidPort(t *testing.T) {
	pki := buildTestPKI(t)
	hubAddr, _, stop := startTLSEcho(t, pki)
	defer stop()

	tr, err := NewSOCKS5TLS(SOCKS5TLSConfig{
		HubAddr:        hubAddr,
		AdminAddr:      hubAddr,
		CACertFile:     pki.CACertFile,
		ClientCertFile: pki.ClientCertFile,
		ClientKeyFile:  pki.ClientKeyFile,
	})
	if err != nil {
		t.Fatalf("NewSOCKS5TLS: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	for _, p := range []int{0, -1, 65536, 1_000_000} {
		if _, err := tr.DialSOCKS(context.Background(), p); err == nil {
			t.Errorf("port=%d: expected error, got nil", p)
		}
	}
}

func TestSOCKS5TLS_DialSOCKS_HonorsCancelledContext(t *testing.T) {
	pki := buildTestPKI(t)

	// Listener exists so the TCP layer can succeed; a cancelled ctx
	// should still fail promptly during handshake or preamble write.
	hubAddr, _, stop := startTLSEcho(t, pki)
	defer stop()

	tr, err := NewSOCKS5TLS(SOCKS5TLSConfig{
		HubAddr:        hubAddr,
		AdminAddr:      hubAddr,
		CACertFile:     pki.CACertFile,
		ClientCertFile: pki.ClientCertFile,
		ClientKeyFile:  pki.ClientKeyFile,
		DialTimeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewSOCKS5TLS: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, derr := tr.DialSOCKS(ctx, 9050)
	elapsed := time.Since(start)
	if derr == nil {
		t.Fatal("DialSOCKS with cancelled ctx returned nil error")
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("cancelled-ctx dial took %s; want <500ms", elapsed)
	}
}

func TestSOCKS5TLS_AdminClient_Returns200(t *testing.T) {
	pki := buildTestPKI(t)

	adminAddr, stop := startTLSAdmin(t, pki)
	defer stop()

	tr, err := NewSOCKS5TLS(SOCKS5TLSConfig{
		HubAddr:        adminAddr, // unused here but required
		AdminAddr:      adminAddr,
		CACertFile:     pki.CACertFile,
		ClientCertFile: pki.ClientCertFile,
		ClientKeyFile:  pki.ClientKeyFile,
		DialTimeout:    3 * time.Second,
		ClientTimeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewSOCKS5TLS: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	client := tr.AdminClient()
	if client == nil {
		t.Fatal("AdminClient() returned nil")
	}

	// The URL host doesn't need to match adminAddr: the custom
	// DialTLSContext always routes to AdminAddr. SNI is set from the
	// dial target, so use https://localhost to match the server cert.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://localhost/ping", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
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
	if string(body) != "pong" {
		t.Fatalf("body = %q, want %q", body, "pong")
	}
}

func TestSOCKS5TLS_AdminClient_SharedInstance(t *testing.T) {
	pki := buildTestPKI(t)

	tr, err := NewSOCKS5TLS(SOCKS5TLSConfig{
		HubAddr:        "127.0.0.1:1",
		AdminAddr:      "127.0.0.1:1",
		CACertFile:     pki.CACertFile,
		ClientCertFile: pki.ClientCertFile,
		ClientKeyFile:  pki.ClientKeyFile,
	})
	if err != nil {
		t.Fatalf("NewSOCKS5TLS: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	a := tr.AdminClient()
	b := tr.AdminClient()
	if a == nil || b == nil {
		t.Fatal("AdminClient returned nil")
	}
	if a != b {
		t.Fatalf("AdminClient returned distinct clients: %p vs %p", a, b)
	}
}

func TestSOCKS5TLS_Close_Idempotent(t *testing.T) {
	pki := buildTestPKI(t)

	tr, err := NewSOCKS5TLS(SOCKS5TLSConfig{
		HubAddr:        "127.0.0.1:1",
		AdminAddr:      "127.0.0.1:1",
		CACertFile:     pki.CACertFile,
		ClientCertFile: pki.ClientCertFile,
		ClientKeyFile:  pki.ClientKeyFile,
	})
	if err != nil {
		t.Fatalf("NewSOCKS5TLS: %v", err)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Close() panicked: %v", r)
		}
	}()

	if err := tr.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := tr.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := tr.Close(); err != nil {
		t.Fatalf("third Close: %v", err)
	}
}

func TestSOCKS5TLS_InterfaceSatisfied(t *testing.T) {
	// Compile-time guarantee reinforced at runtime.
	var _ Transport = (*SOCKS5TLS)(nil)

	pki := buildTestPKI(t)
	tr, err := NewSOCKS5TLS(SOCKS5TLSConfig{
		HubAddr:        "127.0.0.1:1",
		AdminAddr:      "127.0.0.1:1",
		CACertFile:     pki.CACertFile,
		ClientCertFile: pki.ClientCertFile,
		ClientKeyFile:  pki.ClientKeyFile,
	})
	if err != nil {
		t.Fatalf("NewSOCKS5TLS: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	var iface Transport = tr
	if iface.AdminClient() == nil {
		t.Fatal("Transport.AdminClient() returned nil")
	}
}

func TestSOCKS5TLS_NewSOCKS5TLS_ValidatesRequiredFields(t *testing.T) {
	pki := buildTestPKI(t)

	base := SOCKS5TLSConfig{
		HubAddr:        "hub:9443",
		AdminAddr:      "hub:9444",
		CACertFile:     pki.CACertFile,
		ClientCertFile: pki.ClientCertFile,
		ClientKeyFile:  pki.ClientKeyFile,
	}

	// Baseline: all required fields present → succeeds.
	if _, err := NewSOCKS5TLS(base); err != nil {
		t.Fatalf("baseline NewSOCKS5TLS failed: %v", err)
	}

	cases := []struct {
		name string
		mut  func(c *SOCKS5TLSConfig)
	}{
		{"missing HubAddr", func(c *SOCKS5TLSConfig) { c.HubAddr = "" }},
		{"missing AdminAddr", func(c *SOCKS5TLSConfig) { c.AdminAddr = "" }},
		{"missing CACertFile", func(c *SOCKS5TLSConfig) { c.CACertFile = "" }},
		{"missing ClientCertFile", func(c *SOCKS5TLSConfig) { c.ClientCertFile = "" }},
		{"missing ClientKeyFile", func(c *SOCKS5TLSConfig) { c.ClientKeyFile = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			tc.mut(&c)
			if _, err := NewSOCKS5TLS(c); err == nil {
				t.Fatalf("%s: expected error, got nil", tc.name)
			}
		})
	}
}

func TestSOCKS5TLS_NewSOCKS5TLS_RejectsBadCAFile(t *testing.T) {
	pki := buildTestPKI(t)

	// Non-existent CA file.
	_, err := NewSOCKS5TLS(SOCKS5TLSConfig{
		HubAddr:        "hub:9443",
		AdminAddr:      "hub:9444",
		CACertFile:     filepath.Join(t.TempDir(), "nope.pem"),
		ClientCertFile: pki.ClientCertFile,
		ClientKeyFile:  pki.ClientKeyFile,
	})
	if err == nil {
		t.Fatal("expected error for missing ca file, got nil")
	}

	// CA file that exists but contains no valid certs.
	badCA := filepath.Join(t.TempDir(), "bad-ca.pem")
	if werr := os.WriteFile(badCA, []byte("not a pem block at all"), 0o600); werr != nil {
		t.Fatalf("write bad ca: %v", werr)
	}
	_, err = NewSOCKS5TLS(SOCKS5TLSConfig{
		HubAddr:        "hub:9443",
		AdminAddr:      "hub:9444",
		CACertFile:     badCA,
		ClientCertFile: pki.ClientCertFile,
		ClientKeyFile:  pki.ClientKeyFile,
	})
	if err == nil {
		t.Fatal("expected error for bad ca content, got nil")
	}
}

func TestSOCKS5TLS_NewSOCKS5TLS_AppliesDefaults(t *testing.T) {
	pki := buildTestPKI(t)
	tr, err := NewSOCKS5TLS(SOCKS5TLSConfig{
		HubAddr:        "hub:9443",
		AdminAddr:      "hub:9444",
		CACertFile:     pki.CACertFile,
		ClientCertFile: pki.ClientCertFile,
		ClientKeyFile:  pki.ClientKeyFile,
	})
	if err != nil {
		t.Fatalf("NewSOCKS5TLS: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	if tr.cfg.DialTimeout != defaultSOCKS5TLSDialTimeout {
		t.Errorf("DialTimeout = %s, want %s", tr.cfg.DialTimeout, defaultSOCKS5TLSDialTimeout)
	}
	if tr.cfg.ClientTimeout != defaultSOCKS5TLSClientTimeout {
		t.Errorf("ClientTimeout = %s, want %s", tr.cfg.ClientTimeout, defaultSOCKS5TLSClientTimeout)
	}
	if tr.httpClient.Timeout != defaultSOCKS5TLSClientTimeout {
		t.Errorf("httpClient.Timeout = %s, want %s", tr.httpClient.Timeout, defaultSOCKS5TLSClientTimeout)
	}
	if tr.tlsConfig == nil {
		t.Fatal("tlsConfig is nil")
	}
	if len(tr.tlsConfig.Certificates) != 1 {
		t.Errorf("tlsConfig.Certificates has %d entries, want 1", len(tr.tlsConfig.Certificates))
	}
	if tr.tlsConfig.RootCAs == nil {
		t.Error("tlsConfig.RootCAs is nil")
	}
}
