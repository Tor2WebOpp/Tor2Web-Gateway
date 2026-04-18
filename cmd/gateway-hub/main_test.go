package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gateway/internal/config"
	"gateway/internal/hub"
)

// writeConfig writes a minimal hub-mode YAML config file to the given path.
// MinInstances is intentionally 0 so the Tor binary is never spawned during
// tests; gateway-hub is designed to handle this case by skipping torpool
// startup entirely.
func writeConfig(t *testing.T, path, dataDir string) {
	t.Helper()
	yaml := `mode: remote
node_type: hub
hub_url: "http://127.0.0.1:9080"
transport:
  kind: wireguard
hub:
  listen_admin: "127.0.0.1:0"
  data_dir: "` + filepath.ToSlash(dataDir) + `"
tor:
  min_instances: 0
logging:
  level: warn
  format: json
  output: stdout
admin:
  enabled: false
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

// writeAdminConfig writes a hub-mode YAML config with the P3 admin gate
// enabled. AuditDataDir lives under the same data directory so the
// test's t.TempDir cleanup wipes it. SessionIdleTTL/SessionAbsoluteTTL
// are spelled out so config.fillDefaults does not promote them while
// the rest of the file is parsed.
func writeAdminConfig(t *testing.T, path, dataDir, slug, tok1, tok2 string) {
	t.Helper()
	yaml := `mode: remote
node_type: hub
hub_url: "http://127.0.0.1:9080"
transport:
  kind: wireguard
hub:
  listen_admin: "127.0.0.1:0"
  data_dir: "` + filepath.ToSlash(dataDir) + `"
tor:
  min_instances: 0
logging:
  level: warn
  format: json
  output: stdout
admin:
  enabled: true
  slug: "` + slug + `"
  token1: "` + tok1 + `"
  token2: "` + tok2 + `"
  session_idle_ttl: 15m
  session_absolute_ttl: 8h
  audit_data_dir: "` + filepath.ToSlash(filepath.Join(dataDir, "audit")) + `"
  lockout:
    soft_threshold: 3
    soft_window: 60s
    soft_backoff: 30s
    hard_threshold: 10
    hard_window: 10m
    hard_ban: 1h
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write admin config: %v", err)
	}
}

// TestRun_StartsAndServesGlobals boots gateway-hub end-to-end, presents a
// freshly-registered client cert, GETs /v1/globals, and asserts the run()
// function exits cleanly within the shutdown grace after ctx cancellation.
func TestRun_StartsAndServesGlobals(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "hub-data")
	cfgPath := filepath.Join(tmp, "config.yaml")
	writeConfig(t, cfgPath, dataDir)

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	// Bind an ephemeral port up front so we know the address before run()
	// starts serving. runWithListener adopts the listener verbatim.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runWithListener(ctx, cfg, ln)
	}()

	// Wait until the hub has written the CA cert to disk. CA generation
	// happens after all cleanup-sensitive wiring, so seeing the file on
	// disk is a reliable "ready" signal — in particular it implies the
	// adminServer has been constructed and ServeTLS is about to accept.
	// The raw TCP listener on our side accepts immediately so we cannot
	// rely on Dial succeeding; polling the file is deterministic.
	caCertPath := filepath.Join(dataDir, "ca.crt")
	if !waitForFile(caCertPath, 5*time.Second) {
		cancel()
		<-runDone
		t.Fatalf("CA cert never appeared at %s", caCertPath)
	}
	caPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		cancel()
		<-runDone
		t.Fatalf("read ca cert: %v", err)
	}
	rootPool := x509.NewCertPool()
	if !rootPool.AppendCertsFromPEM(caPEM) {
		cancel()
		<-runDone
		t.Fatalf("parse ca PEM")
	}

	// Register a node to obtain a client cert. The register endpoint is
	// unauthenticated so an empty-client-cert handshake suffices.
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    rootPool,
				ServerName: "localhost",
				MinVersion: tls.VersionTLS12,
			},
		},
	}
	csrPEM, clientKey := newClientCSR(t, "edge-smoke")
	regBody, _ := json.Marshal(map[string]string{
		"node_id":   "edge-smoke",
		"node_type": "proxy",
		"csr_pem":   csrPEM,
	})
	resp, err := client.Post("https://"+addr+"/v1/nodes/register",
		"application/json", bytes.NewReader(regBody))
	if err != nil {
		cancel()
		<-runDone
		t.Fatalf("register: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		cancel()
		<-runDone
		t.Fatalf("register status %d: %s", resp.StatusCode, body)
	}
	var regResp hub.RegisterResponse
	if err := json.Unmarshal(body, &regResp); err != nil {
		cancel()
		<-runDone
		t.Fatalf("register decode: %v", err)
	}

	// Build an mTLS client and hit a protected endpoint.
	block, _ := pem.Decode([]byte(regResp.CertPEM))
	if block == nil {
		cancel()
		<-runDone
		t.Fatalf("decode client cert")
	}
	authClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      rootPool,
				ServerName:   "localhost",
				Certificates: []tls.Certificate{{Certificate: [][]byte{block.Bytes}, PrivateKey: clientKey}},
				MinVersion:   tls.VersionTLS12,
			},
		},
	}
	gResp, err := authClient.Get("https://" + addr + "/v1/globals")
	if err != nil {
		cancel()
		<-runDone
		t.Fatalf("get globals: %v", err)
	}
	gBody, _ := io.ReadAll(gResp.Body)
	gResp.Body.Close()
	if gResp.StatusCode != http.StatusOK {
		cancel()
		<-runDone
		t.Fatalf("globals status %d: %s", gResp.StatusCode, gBody)
	}

	// Trigger graceful shutdown and confirm run() returns within the grace
	// window. shutdownGrace is 30s in production; 5s is ample here because
	// no SSE streams are open and torpool was skipped.
	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("run did not exit within 5s of cancel")
	}
}

// TestRun_AdminGateEnabled boots gateway-hub with the P3 admin gate
// enabled and confirms the bootstrap path: a fresh request to
// /<slug>/<token1>/<token2> issues a session cookie + 302; a follow-up
// request with the cookie to /api/me returns 200 and JSON.
//
// The admin path bypasses mTLS by design — the URL itself is the
// credential — so the test client does not present a client certificate,
// only the CA root for server verification.
func TestRun_AdminGateEnabled(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "hub-data")
	cfgPath := filepath.Join(tmp, "config.yaml")
	const (
		slug = "smokehub32slug32slug32slug32slug"
		tok1 = "smokehub32token1aaaaaaaaaaaaaaaa"
		tok2 = "smokehub32token2bbbbbbbbbbbbbbbb"
	)
	writeAdminConfig(t, cfgPath, dataDir, slug, tok1, tok2)

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() {
		runDone <- runWithListener(ctx, cfg, ln)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-runDone:
		case <-time.After(5 * time.Second):
			t.Logf("hub run did not exit within 5s of cancel")
		}
	})

	caCertPath := filepath.Join(dataDir, "ca.crt")
	if !waitForFile(caCertPath, 5*time.Second) {
		t.Fatalf("CA cert never appeared at %s", caCertPath)
	}
	caPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		t.Fatalf("read ca: %v", err)
	}
	rootPool := x509.NewCertPool()
	if !rootPool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("parse ca PEM")
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    rootPool,
				ServerName: "localhost",
				MinVersion: tls.VersionTLS12,
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	prefix := "/" + slug + "/" + tok1 + "/" + tok2
	resp, err := client.Get("https://" + addr + prefix)
	if err != nil {
		t.Fatalf("admin GET: %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("admin first hit: status = %d, want 302", resp.StatusCode)
	}
	var sessionCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "gw_adm" {
			sessionCookie = c
			break
		}
	}
	resp.Body.Close()
	if sessionCookie == nil {
		t.Fatalf("first admin hit did not issue gw_adm cookie")
	}

	req, _ := http.NewRequest(http.MethodGet, "https://"+addr+prefix+"/api/me", nil)
	req.AddCookie(&http.Cookie{Name: "gw_adm", Value: sessionCookie.Value})
	r2, err := client.Do(req)
	if err != nil {
		t.Fatalf("/api/me GET: %v", err)
	}
	body, _ := io.ReadAll(r2.Body)
	r2.Body.Close()
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("/api/me status = %d, body = %q", r2.StatusCode, body)
	}
	if !strings.Contains(string(body), `"node_type"`) {
		t.Fatalf("/api/me body missing node_type: %q", body)
	}
}

// TestRun_RejectsNonHubNodeType confirms the role check in run() prevents
// the binary from accidentally being pointed at an edge-mode config.
func TestRun_RejectsNonHubNodeType(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		Mode:     config.ModeRemote,
		NodeType: config.NodeTypeProxy, // deliberately wrong
		Hub: config.HubConf{
			DataDir: t.TempDir(),
		},
	}
	err := run(context.Background(), cfg)
	if err == nil {
		t.Fatalf("expected node_type rejection, got nil")
	}
	if !strings.Contains(err.Error(), "node_type") {
		t.Fatalf("expected error to mention node_type, got %v", err)
	}
}

// TestRun_RejectsMissingDataDir ensures a zero-value Hub.DataDir is caught
// before any subsystem is spun up.
func TestRun_RejectsMissingDataDir(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		Mode:     config.ModeRemote,
		NodeType: config.NodeTypeHub,
	}
	err := run(context.Background(), cfg)
	if err == nil {
		t.Fatalf("expected data_dir rejection, got nil")
	}
	if !strings.Contains(err.Error(), "data_dir") {
		t.Fatalf("expected error to mention data_dir, got %v", err)
	}
}

// TestRun_RejectsNilConfig documents that run() is defensive about its
// required argument — important because the exported helper is used by
// tests and might be called with a stale/partial config.
func TestRun_RejectsNilConfig(t *testing.T) {
	t.Parallel()
	if err := run(context.Background(), nil); err == nil {
		t.Fatal("expected error on nil config")
	}
}

// newClientCSR produces a PEM-encoded CSR whose CommonName is nodeID,
// signed with a fresh P-256 key. Returns the PEM and the private key so
// the caller can immediately construct a tls.Certificate for mTLS use.
func newClientCSR(t *testing.T, nodeID string) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: nodeID}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), key
}

// waitForFile returns true as soon as path exists on disk, or false if
// the deadline elapses first. Used as a "hub is ready" probe: CA cert
// creation happens inside run() after all state-bearing subsystems are
// wired, so the file's presence is a deterministic readiness signal.
func waitForFile(path string, deadline time.Duration) bool {
	stop := time.Now().Add(deadline)
	for time.Now().Before(stop) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return false
}
