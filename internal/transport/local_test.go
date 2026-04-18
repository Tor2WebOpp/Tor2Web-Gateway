package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// newUnixSocketPath returns a temp-dir path suitable for net.Listen("unix", ...).
// On Windows the AF_UNIX SOCK_STREAM family is supported on Win10+/Win11 and
// the test machine is Win11, so no platform guard is applied preemptively.
func newUnixSocketPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "admin.sock")
}

func TestLocal_AdminClient_UnixSocket(t *testing.T) {
	sockPath := newUnixSocketPath(t)

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("net.Listen unix %q: %v", sockPath, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok-from-unix")
	})

	srv := &http.Server{Handler: mux}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Logf("srv.Serve returned %v", err)
		}
	}()
	t.Cleanup(func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		<-done
	})

	tr := NewLocal(LocalConfig{SocketPath: sockPath})
	t.Cleanup(func() { _ = tr.Close() })

	client := tr.AdminClient()
	if client == nil {
		t.Fatal("AdminClient() returned nil")
	}

	// The host portion of the URL is irrelevant; the custom DialContext
	// always routes to the unix socket.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://unix/hello", nil)
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
	if got := string(body); got != "ok-from-unix" {
		t.Fatalf("body = %q, want %q", got, "ok-from-unix")
	}
}

func TestLocal_DialSOCKS_ReachesLoopback(t *testing.T) {
	// Reserve an ephemeral loopback port by binding to 127.0.0.1:0.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp 127.0.0.1:0: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	port := ln.Addr().(*net.TCPAddr).Port

	accepted := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			accepted <- err
			return
		}
		defer c.Close()
		buf := make([]byte, 1)
		if _, err := io.ReadFull(c, buf); err != nil {
			accepted <- err
			return
		}
		accepted <- nil
	}()

	tr := NewLocal(LocalConfig{SocketPath: newUnixSocketPath(t)})
	t.Cleanup(func() { _ = tr.Close() })

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := tr.DialSOCKS(ctx, port)
	if err != nil {
		t.Fatalf("DialSOCKS port=%d: %v", port, err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte{0x05}); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := <-accepted; err != nil {
		t.Fatalf("accept/read failed: %v", err)
	}

	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("dial+write+accept took %s; want <100ms on loopback", d)
	}
}

func TestLocal_DialSOCKS_HonorsCancelledContext(t *testing.T) {
	tr := NewLocal(LocalConfig{
		SocketPath:  newUnixSocketPath(t),
		DialTimeout: 5 * time.Second, // large: proves ctx wins, not the dialer
	})
	t.Cleanup(func() { _ = tr.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	// Port 1 is reserved/unusable; on a cancelled ctx the dial must
	// return immediately regardless of port reachability.
	start := time.Now()
	_, err := tr.DialSOCKS(ctx, 1)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("DialSOCKS with cancelled ctx returned nil error")
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("cancelled-ctx dial took %s; want <200ms", elapsed)
	}
}

func TestLocal_DialSOCKS_RejectsInvalidPort(t *testing.T) {
	tr := NewLocal(LocalConfig{SocketPath: newUnixSocketPath(t)})
	t.Cleanup(func() { _ = tr.Close() })

	for _, p := range []int{0, -1, 65536} {
		if _, err := tr.DialSOCKS(context.Background(), p); err == nil {
			t.Errorf("port=%d: expected error, got nil", p)
		}
	}
}

func TestLocal_NewLocal_AppliesDefaults(t *testing.T) {
	tr := NewLocal(LocalConfig{SocketPath: newUnixSocketPath(t)})
	t.Cleanup(func() { _ = tr.Close() })

	if tr.cfg.SOCKSHost != defaultLocalSOCKSHost {
		t.Errorf("SOCKSHost = %q, want %q", tr.cfg.SOCKSHost, defaultLocalSOCKSHost)
	}
	if tr.cfg.DialTimeout != defaultLocalDialTimeout {
		t.Errorf("DialTimeout = %s, want %s", tr.cfg.DialTimeout, defaultLocalDialTimeout)
	}
	if tr.cfg.ClientTimeout != defaultLocalClientTimeout {
		t.Errorf("ClientTimeout = %s, want %s", tr.cfg.ClientTimeout, defaultLocalClientTimeout)
	}
	if tr.httpClient == nil {
		t.Error("httpClient is nil")
	}
	if tr.httpClient.Timeout != defaultLocalClientTimeout {
		t.Errorf("httpClient.Timeout = %s, want %s", tr.httpClient.Timeout, defaultLocalClientTimeout)
	}
}

func TestLocal_NewLocal_PreservesExplicitValues(t *testing.T) {
	cfg := LocalConfig{
		SocketPath:    newUnixSocketPath(t),
		SOCKSHost:     "10.0.0.1",
		DialTimeout:   123 * time.Millisecond,
		ClientTimeout: 456 * time.Millisecond,
	}
	tr := NewLocal(cfg)
	t.Cleanup(func() { _ = tr.Close() })

	if tr.cfg.SOCKSHost != "10.0.0.1" {
		t.Errorf("SOCKSHost overwritten: %q", tr.cfg.SOCKSHost)
	}
	if tr.cfg.DialTimeout != 123*time.Millisecond {
		t.Errorf("DialTimeout overwritten: %s", tr.cfg.DialTimeout)
	}
	if tr.cfg.ClientTimeout != 456*time.Millisecond {
		t.Errorf("ClientTimeout overwritten: %s", tr.cfg.ClientTimeout)
	}
	if tr.httpClient.Timeout != 456*time.Millisecond {
		t.Errorf("httpClient.Timeout = %s, want 456ms", tr.httpClient.Timeout)
	}
}

func TestLocal_Close_Idempotent(t *testing.T) {
	tr := NewLocal(LocalConfig{SocketPath: newUnixSocketPath(t)})

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
	// Third time for good measure — still no panic, still nil.
	if err := tr.Close(); err != nil {
		t.Fatalf("third Close: %v", err)
	}
}

func TestLocal_InterfaceSatisfied(t *testing.T) {
	// This is a compile-time check reinforced at runtime: confirms that
	// the public API shape matches the Transport contract and keeps
	// refactors honest.
	var _ Transport = (*Local)(nil)

	var tr Transport = NewLocal(LocalConfig{SocketPath: newUnixSocketPath(t)})
	t.Cleanup(func() { _ = tr.Close() })

	if tr.AdminClient() == nil {
		t.Fatal("Transport.AdminClient() returned nil")
	}
}

// TestLocal_AdminClient_SharedInstance guards against accidental changes
// that allocate a fresh client per call; callers rely on the same
// *http.Client being reused so that idle-conn state persists.
func TestLocal_AdminClient_SharedInstance(t *testing.T) {
	tr := NewLocal(LocalConfig{SocketPath: newUnixSocketPath(t)})
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

// Sanity: the package-level Kind constants exist and match the spec.
func TestKind_Values(t *testing.T) {
	cases := []struct {
		got, want Kind
	}{
		{KindLocal, "local"},
		{KindWireguard, "wireguard"},
		{KindHTTPSTunnel, "https_tunnel"},
		{KindSOCKS5TLS, "socks5_tls"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("Kind %q != %q", c.got, c.want)
		}
	}
	// String() via Kind's underlying type
	if fmt.Sprintf("%s", KindLocal) != "local" {
		t.Errorf("KindLocal stringifies wrong: %s", KindLocal)
	}
}
