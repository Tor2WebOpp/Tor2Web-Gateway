package transport

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"gateway/internal/config"
)

// newWireguardForLoopback returns a *Wireguard whose PeerInternalIP is
// 127.0.0.1 — the only address available on a build machine that has no
// real wg overlay. The SOCKS/admin code paths are indifferent to the
// underlying L3 mechanism, so loopback exercises them faithfully.
func newWireguardForLoopback(t *testing.T, cfg WireguardConfig) *Wireguard {
	t.Helper()
	if cfg.PeerInternalIP == "" {
		cfg.PeerInternalIP = "127.0.0.1"
	}
	tr, err := NewWireguard(cfg)
	if err != nil {
		t.Fatalf("NewWireguard: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	return tr
}

func TestWireguard_DialSOCKS_ReachesLoopback(t *testing.T) {
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

	tr := newWireguardForLoopback(t, WireguardConfig{})

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

	if d := time.Since(start); d > 200*time.Millisecond {
		t.Fatalf("dial+write+accept took %s; want <200ms on loopback", d)
	}
}

func TestWireguard_DialSOCKS_HonorsCancelledContext(t *testing.T) {
	tr := newWireguardForLoopback(t, WireguardConfig{
		DialTimeout: 5 * time.Second, // large: proves ctx wins, not the dialer
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

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

func TestWireguard_DialSOCKS_RejectsInvalidPort(t *testing.T) {
	tr := newWireguardForLoopback(t, WireguardConfig{})
	for _, p := range []int{0, -1, 65536} {
		if _, err := tr.DialSOCKS(context.Background(), p); err == nil {
			t.Errorf("port=%d: expected error, got nil", p)
		}
	}
}

func TestWireguard_AdminClient_HitsHTTPTestServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "pong")
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	u, err := net.ResolveTCPAddr("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("resolve httptest URL %q: %v", srv.URL, err)
	}

	// Point the Wireguard transport at the httptest listener, then dial
	// any URL host — the custom DialContext always routes to the
	// configured PeerInternalIP:AdminPort regardless of URL host.
	tr := newWireguardForLoopback(t, WireguardConfig{
		AdminPort: u.Port,
	})

	client := tr.AdminClient()
	if client == nil {
		t.Fatal("AdminClient() returned nil")
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://hub.internal/ping", nil)
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
	if got := string(body); got != "pong" {
		t.Fatalf("body = %q, want %q", got, "pong")
	}
}

func TestWireguard_AdminClient_SharedInstance(t *testing.T) {
	tr := newWireguardForLoopback(t, WireguardConfig{})
	a := tr.AdminClient()
	b := tr.AdminClient()
	if a == nil || b == nil {
		t.Fatal("AdminClient returned nil")
	}
	if a != b {
		t.Fatalf("AdminClient returned distinct clients: %p vs %p", a, b)
	}
}

func TestWireguard_NewWireguard_AppliesDefaults(t *testing.T) {
	tr, err := NewWireguard(WireguardConfig{PeerInternalIP: "10.0.0.1"})
	if err != nil {
		t.Fatalf("NewWireguard: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	if tr.cfg.AdminPort != defaultWireguardAdminPort {
		t.Errorf("AdminPort = %d, want %d", tr.cfg.AdminPort, defaultWireguardAdminPort)
	}
	if tr.cfg.DialTimeout != defaultWireguardDialTimeout {
		t.Errorf("DialTimeout = %s, want %s", tr.cfg.DialTimeout, defaultWireguardDialTimeout)
	}
	if tr.cfg.ClientTimeout != defaultWireguardClientTimeout {
		t.Errorf("ClientTimeout = %s, want %s", tr.cfg.ClientTimeout, defaultWireguardClientTimeout)
	}
	if tr.httpClient == nil {
		t.Fatal("httpClient is nil")
	}
	if tr.httpClient.Timeout != defaultWireguardClientTimeout {
		t.Errorf("httpClient.Timeout = %s, want %s", tr.httpClient.Timeout, defaultWireguardClientTimeout)
	}
}

func TestWireguard_NewWireguard_PreservesExplicitValues(t *testing.T) {
	cfg := WireguardConfig{
		PeerInternalIP: "10.0.0.1",
		AdminPort:      7777,
		DialTimeout:    111 * time.Millisecond,
		ClientTimeout:  333 * time.Millisecond,
	}
	tr, err := NewWireguard(cfg)
	if err != nil {
		t.Fatalf("NewWireguard: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	if tr.cfg.AdminPort != 7777 {
		t.Errorf("AdminPort overwritten: %d", tr.cfg.AdminPort)
	}
	if tr.cfg.DialTimeout != 111*time.Millisecond {
		t.Errorf("DialTimeout overwritten: %s", tr.cfg.DialTimeout)
	}
	if tr.cfg.ClientTimeout != 333*time.Millisecond {
		t.Errorf("ClientTimeout overwritten: %s", tr.cfg.ClientTimeout)
	}
	if tr.httpClient.Timeout != 333*time.Millisecond {
		t.Errorf("httpClient.Timeout = %s, want 333ms", tr.httpClient.Timeout)
	}
}

func TestWireguard_NewWireguard_RejectsBadConfig(t *testing.T) {
	if _, err := NewWireguard(WireguardConfig{}); err == nil {
		t.Error("NewWireguard with empty PeerInternalIP returned nil error")
	}
	if _, err := NewWireguard(WireguardConfig{PeerInternalIP: "10.0.0.1", AdminPort: 70000}); err == nil {
		t.Error("NewWireguard with out-of-range AdminPort returned nil error")
	}
}

func TestWireguard_Close_Idempotent(t *testing.T) {
	tr, err := NewWireguard(WireguardConfig{PeerInternalIP: "127.0.0.1"})
	if err != nil {
		t.Fatalf("NewWireguard: %v", err)
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

func TestWireguard_InterfaceSatisfied(t *testing.T) {
	var _ Transport = (*Wireguard)(nil)

	raw, err := NewWireguard(WireguardConfig{PeerInternalIP: "127.0.0.1"})
	if err != nil {
		t.Fatalf("NewWireguard: %v", err)
	}
	var tr Transport = raw
	t.Cleanup(func() { _ = tr.Close() })

	if tr.AdminClient() == nil {
		t.Fatal("Transport.AdminClient() returned nil")
	}
}

func TestParseWireguardConfigFromTop_DerivesFromHubURL(t *testing.T) {
	top := &config.Config{
		HubURL: "http://10.0.0.1:9081",
		Transport: config.TransportConf{
			Wireguard: config.WireguardConf{
				Interface:      "wg0",
				PrivateKeyFile: "/etc/gateway/wg-private.key",
				PeerPubkey:     "abc=",
				PeerEndpoint:   "hub.lan:51820",
				PeerAllowedIPs: "10.0.0.1/32",
				SelfIP:         "10.0.0.42/24",
			},
		},
	}

	got, err := ParseWireguardConfigFromTop(top)
	if err != nil {
		t.Fatalf("ParseWireguardConfigFromTop: %v", err)
	}
	if got.PeerInternalIP != "10.0.0.1" {
		t.Errorf("PeerInternalIP = %q, want %q", got.PeerInternalIP, "10.0.0.1")
	}
	if got.AdminPort != 9081 {
		t.Errorf("AdminPort = %d, want 9081", got.AdminPort)
	}
	if got.Interface != "wg0" {
		t.Errorf("Interface = %q, want %q", got.Interface, "wg0")
	}
	if got.SelfIP != "10.0.0.42/24" {
		t.Errorf("SelfIP = %q, want %q", got.SelfIP, "10.0.0.42/24")
	}
}

func TestParseWireguardConfigFromTop_HubURLWithoutPort(t *testing.T) {
	top := &config.Config{
		HubURL: "http://10.0.0.1",
	}
	got, err := ParseWireguardConfigFromTop(top)
	if err != nil {
		t.Fatalf("ParseWireguardConfigFromTop: %v", err)
	}
	if got.PeerInternalIP != "10.0.0.1" {
		t.Errorf("PeerInternalIP = %q, want %q", got.PeerInternalIP, "10.0.0.1")
	}
	// AdminPort stays zero; NewWireguard will apply the 9080 default.
	if got.AdminPort != 0 {
		t.Errorf("AdminPort = %d, want 0 (NewWireguard applies default)", got.AdminPort)
	}
	tr, err := NewWireguard(got)
	if err != nil {
		t.Fatalf("NewWireguard from parsed config: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	if tr.cfg.AdminPort != defaultWireguardAdminPort {
		t.Errorf("AdminPort default not applied: %d", tr.cfg.AdminPort)
	}
}

func TestParseWireguardConfigFromTop_RejectsEmptyHubURL(t *testing.T) {
	if _, err := ParseWireguardConfigFromTop(&config.Config{}); err == nil {
		t.Error("expected error when hub_url is empty")
	}
	if _, err := ParseWireguardConfigFromTop(nil); err == nil {
		t.Error("expected error on nil config")
	}
}

func TestParseWireguardConfigFromTop_RejectsMalformedHubURL(t *testing.T) {
	// A URL whose port is non-numeric is rejected by net/url up front;
	// check that an impossible port surfaces as a WireguardConfig error.
	bad := &config.Config{HubURL: "http://10.0.0.1:notaport"}
	if _, err := ParseWireguardConfigFromTop(bad); err == nil {
		t.Error("expected error for malformed hub_url port")
	}
}

// Sanity-check on the default port value so the const stays in sync with
// the spec's `listen_admin: 10.0.0.1:9080` requirement.
func TestWireguard_DefaultAdminPortMatchesSpec(t *testing.T) {
	if defaultWireguardAdminPort != 9080 {
		t.Fatalf("defaultWireguardAdminPort = %d, want 9080 (per spec)", defaultWireguardAdminPort)
	}
	// And formatting of host:port stays portable.
	got := net.JoinHostPort("10.0.0.1", strconv.Itoa(defaultWireguardAdminPort))
	if got != "10.0.0.1:9080" {
		t.Fatalf("JoinHostPort gave %q, want 10.0.0.1:9080", got)
	}
}
