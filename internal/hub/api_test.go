package hub

import (
	"bufio"
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
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gateway/internal/config"
	"gateway/internal/shared"
)

// apiFixture bundles the collaborators wired behind a mTLS-capable
// httptest.Server so each test can focus on a single endpoint.
type apiFixture struct {
	t      *testing.T
	dir    string
	reg    *Registry
	ca     *CA
	nodes  *NodeStore
	api    *API
	server *httptest.Server
}

// newAPIFixture builds a full hub HTTP API over TLS. The returned fixture
// exposes helpers for making authenticated and unauthenticated requests
// and for installing node assignments without going through the wire.
func newAPIFixture(t *testing.T) *apiFixture {
	t.Helper()

	dir := t.TempDir()
	reg, err := New(dir)
	if err != nil {
		t.Fatalf("new registry: %v", err)
	}
	t.Cleanup(func() { _ = reg.Close() })

	ca, err := NewCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("new ca: %v", err)
	}

	nodes := NewNodeStore()
	api := NewAPI(reg, ca, nodes, "")

	// Server leaf signed by the CA so mTLS negotiation can complete.
	serverCert := newServerCert(t, ca)

	srv := httptest.NewUnstartedServer(api.Handler())
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    ca.CertPool(),
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return &apiFixture{
		t:      t,
		dir:    dir,
		reg:    reg,
		ca:     ca,
		nodes:  nodes,
		api:    api,
		server: srv,
	}
}

// newServerCert issues a TLS server certificate whose SAN covers 127.0.0.1
// and localhost — both of which httptest may report.
func newServerCert(t *testing.T, ca *CA) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(9001),
		Subject:      pkix.Name{CommonName: "hub.test"},
		NotBefore:    now.Add(-1 * time.Minute),
		NotAfter:     now.Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "hub.test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.RootCert(), &key.PublicKey, caPrivateKey(t, ca))
	if err != nil {
		t.Fatalf("sign server cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// caPrivateKey extracts the *ecdsa.PrivateKey embedded in ca via
// reflection-free field access. The CA field is unexported, so we cheat by
// round-tripping a test-only CSR through SignCSR and comparing — but a
// cleaner path exists: the CA struct keeps rootKey and we're in the same
// package, so we can read it directly.
func caPrivateKey(t *testing.T, ca *CA) *ecdsa.PrivateKey {
	t.Helper()
	if ca.rootKey == nil {
		t.Fatal("ca has no root key")
	}
	return ca.rootKey
}

// newClientCSR makes a CSR for (nodeID, CN=nodeID) signed by a fresh
// P-256 key. Returns the CSR PEM and the private key for later TLS use.
func newClientCSR(t *testing.T, nodeID string) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: nodeID},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	return string(out), key
}

// authClient builds an *http.Client whose tls.Config presents the supplied
// leaf + key as a client cert and trusts the hub CA as root.
func (f *apiFixture) authClient(certPEM string, key *ecdsa.PrivateKey) *http.Client {
	f.t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		f.t.Fatal("decode cert PEM")
	}
	cert := tls.Certificate{
		Certificate: [][]byte{block.Bytes},
		PrivateKey:  key,
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      f.ca.CertPool(),
				Certificates: []tls.Certificate{cert},
				ServerName:   "hub.test",
				MinVersion:   tls.VersionTLS12,
			},
		},
	}
}

// plainClient is a TLS client with no client cert — used to drive the
// register endpoint and to prove that protected endpoints 401 without
// mTLS.
func (f *apiFixture) plainClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    f.ca.CertPool(),
				ServerName: "hub.test",
				MinVersion: tls.VersionTLS12,
			},
		},
	}
}

// registerNode runs the unauthenticated POST /v1/nodes/register against
// the fixture, returning the response body unmarshalled and the client
// keypair so the caller can immediately build an authenticated client.
func (f *apiFixture) registerNode(nodeID, nodeType string) (RegisterResponse, *ecdsa.PrivateKey) {
	f.t.Helper()
	csrPEM, key := newClientCSR(f.t, nodeID)
	reqBody := RegisterRequest{
		NodeID:   nodeID,
		NodeType: nodeType,
		CSRPEM:   csrPEM,
	}
	buf, _ := json.Marshal(reqBody)
	resp, err := f.plainClient().Post(f.server.URL+"/v1/nodes/register",
		"application/json", bytes.NewReader(buf))
	if err != nil {
		f.t.Fatalf("register: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		f.t.Fatalf("register status %d: %s", resp.StatusCode, body)
	}
	var out RegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		f.t.Fatalf("register decode: %v", err)
	}
	return out, key
}

// --- Tests ---

func TestAPI_ProtectedEndpointRejectsUnauthenticated(t *testing.T) {
	f := newAPIFixture(t)

	resp, err := f.plainClient().Get(f.server.URL + "/v1/tenants")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("want 401, got %d: %s", resp.StatusCode, body)
	}
}

func TestAPI_RegisterNodeReturnsUsableCert(t *testing.T) {
	f := newAPIFixture(t)

	out, key := f.registerNode("edge-alpha", "proxy")
	if out.CertPEM == "" || out.CAPEM == "" || out.Serial == "" {
		t.Fatalf("empty register response: %+v", out)
	}

	// The cert must chain to the advertised CA.
	block, _ := pem.Decode([]byte(out.CertPEM))
	if block == nil {
		t.Fatal("decode cert PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     f.ca.CertPool(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("verify returned cert: %v", err)
	}

	// A subsequent authenticated GET /v1/tenants must succeed.
	client := f.authClient(out.CertPEM, key)
	resp, err := client.Get(f.server.URL + "/v1/tenants")
	if err != nil {
		t.Fatalf("authed request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authed GET /v1/tenants status %d", resp.StatusCode)
	}
}

func TestAPI_GetTenantMissing404(t *testing.T) {
	f := newAPIFixture(t)
	out, key := f.registerNode("edge-beta", "proxy")
	client := f.authClient(out.CertPEM, key)

	resp, err := client.Get(f.server.URL + "/v1/tenants/nope.example")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404, got %d", resp.StatusCode)
	}
}

func TestAPI_PutAndGetTenant(t *testing.T) {
	f := newAPIFixture(t)
	out, key := f.registerNode("edge-gamma", "proxy")
	client := f.authClient(out.CertPEM, key)

	tenant := config.TenantConf{
		Host:    "alpha.example",
		Enabled: true,
		Backends: []config.BackendConf{
			{Addr: strings.Repeat("a", 56) + ".onion", Weight: 1},
		},
	}
	buf, _ := json.Marshal(tenant)
	req, _ := http.NewRequest(http.MethodPut,
		f.server.URL+"/v1/tenants/"+tenant.Host, bytes.NewReader(buf))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("put status %d", resp.StatusCode)
	}

	// List contains it.
	listResp, err := client.Get(f.server.URL + "/v1/tenants")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	defer listResp.Body.Close()
	var list []config.TenantConf
	if err := json.NewDecoder(listResp.Body).Decode(&list); err != nil {
		t.Fatalf("list decode: %v", err)
	}
	if len(list) != 1 || list[0].Host != tenant.Host {
		t.Fatalf("list mismatch: %+v", list)
	}

	// Get returns the same tenant.
	getResp, err := client.Get(f.server.URL + "/v1/tenants/" + tenant.Host)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get status %d", getResp.StatusCode)
	}
	var got config.TenantConf
	if err := json.NewDecoder(getResp.Body).Decode(&got); err != nil {
		t.Fatalf("get decode: %v", err)
	}
	if got.Host != tenant.Host || !got.Enabled {
		t.Fatalf("got %+v", got)
	}
}

func TestAPI_DeleteTenant(t *testing.T) {
	f := newAPIFixture(t)
	out, key := f.registerNode("edge-delta", "proxy")
	client := f.authClient(out.CertPEM, key)

	tenant := config.TenantConf{
		Host:    "del.example",
		Enabled: true,
		Backends: []config.BackendConf{
			{Addr: strings.Repeat("b", 56) + ".onion", Weight: 1},
		},
	}
	buf, _ := json.Marshal(tenant)
	putReq, _ := http.NewRequest(http.MethodPut,
		f.server.URL+"/v1/tenants/"+tenant.Host, bytes.NewReader(buf))
	resp, err := client.Do(putReq)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	resp.Body.Close()

	delReq, _ := http.NewRequest(http.MethodDelete,
		f.server.URL+"/v1/tenants/"+tenant.Host, nil)
	delResp, err := client.Do(delReq)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status %d", delResp.StatusCode)
	}

	// Subsequent GET must 404.
	g, err := client.Get(f.server.URL + "/v1/tenants/" + tenant.Host)
	if err != nil {
		t.Fatalf("get-after-delete: %v", err)
	}
	defer g.Body.Close()
	if g.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404 after delete, got %d", g.StatusCode)
	}
}

func TestAPI_PutGlobalsBroadcasts(t *testing.T) {
	f := newAPIFixture(t)
	out, key := f.registerNode("edge-epsilon", "proxy")
	client := f.authClient(out.CertPEM, key)

	// Subscribe a local collector so we can observe the broadcast without
	// going through SSE (which is exercised in a separate test).
	coll := &collectingSub{done: make(chan struct{}, 8)}
	unsub := f.reg.Subscribe(coll)
	defer unsub()
	<-coll.done // initial snapshot

	g := config.GlobalsConf{
		BlockResponse: config.BlockResponseConf{Default: "drop"},
	}
	buf, _ := json.Marshal(g)
	req, _ := http.NewRequest(http.MethodPut, f.server.URL+"/v1/globals", bytes.NewReader(buf))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("put status %d", resp.StatusCode)
	}

	select {
	case <-coll.done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("no broadcast within 500ms")
	}

	if got := coll.lastType(); got != shared.EventGlobalsUpdate {
		t.Fatalf("want globals_update, got %q", got)
	}

	// GET /v1/globals round-trips the stored value.
	getResp, err := client.Get(f.server.URL + "/v1/globals")
	if err != nil {
		t.Fatalf("get globals: %v", err)
	}
	defer getResp.Body.Close()
	var back config.GlobalsConf
	if err := json.NewDecoder(getResp.Body).Decode(&back); err != nil {
		t.Fatalf("decode globals: %v", err)
	}
	if back.BlockResponse.Default != "drop" {
		t.Fatalf("want default=drop, got %+v", back)
	}
}

func TestAPI_ListNodesIncludesRegistered(t *testing.T) {
	f := newAPIFixture(t)
	out, key := f.registerNode("edge-zeta", "proxy")
	client := f.authClient(out.CertPEM, key)

	resp, err := client.Get(f.server.URL + "/v1/nodes")
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	defer resp.Body.Close()
	var infos []shared.NodeInfo
	if err := json.NewDecoder(resp.Body).Decode(&infos); err != nil {
		t.Fatalf("decode nodes: %v", err)
	}
	if len(infos) != 1 || infos[0].ID != "edge-zeta" {
		t.Fatalf("unexpected nodes: %+v", infos)
	}
}

func TestAPI_DeleteNodeRevokesCert(t *testing.T) {
	f := newAPIFixture(t)
	// admin is the caller that issues the revocation.
	adminOut, adminKey := f.registerNode("edge-admin", "proxy")
	admin := f.authClient(adminOut.CertPEM, adminKey)
	// victim is the node whose cert will be revoked.
	victimOut, victimKey := f.registerNode("edge-victim", "proxy")
	victim := f.authClient(victimOut.CertPEM, victimKey)

	// Sanity: victim can initially hit the API.
	resp, err := victim.Get(f.server.URL + "/v1/tenants")
	if err != nil {
		t.Fatalf("victim pre: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("victim pre status %d", resp.StatusCode)
	}

	// Admin revokes the victim.
	req, _ := http.NewRequest(http.MethodDelete,
		f.server.URL+"/v1/nodes/edge-victim", nil)
	dr, err := admin.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	dr.Body.Close()
	if dr.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status %d", dr.StatusCode)
	}

	// Revoked cert must now receive 403.
	r2, err := victim.Get(f.server.URL + "/v1/tenants")
	if err != nil {
		t.Fatalf("victim post: %v", err)
	}
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(r2.Body)
		t.Fatalf("want 403 after revoke, got %d: %s", r2.StatusCode, body)
	}
}

func TestAPI_ConfigStreamDeliversSnapshotAndUpsert(t *testing.T) {
	f := newAPIFixture(t)
	out, key := f.registerNode("edge-eta", "proxy")

	// Use a raw TLS client so we can read the SSE body line by line.
	dialer := &tls.Dialer{
		Config: &tls.Config{
			RootCAs:      f.ca.CertPool(),
			Certificates: []tls.Certificate{mustTLSCert(t, out.CertPEM, key)},
			ServerName:   "hub.test",
			MinVersion:   tls.VersionTLS12,
		},
	}
	host := strings.TrimPrefix(f.server.URL, "https://")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	req, _ := http.NewRequest(http.MethodGet,
		f.server.URL+"/v1/config/stream", nil)
	if err := req.Write(conn); err != nil {
		t.Fatalf("write req: %v", err)
	}

	br := bufio.NewReader(conn)
	// Read HTTP status line.
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("status line: %v", err)
	}
	if !strings.Contains(statusLine, "200") {
		t.Fatalf("unexpected status: %q", statusLine)
	}
	// Consume headers until blank line.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("header read: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	firstEvent, err := readSSEEvent(br, 2*time.Second)
	if err != nil {
		t.Fatalf("first event: %v", err)
	}
	if firstEvent.Type != shared.EventSnapshot {
		t.Fatalf("want snapshot, got %q", firstEvent.Type)
	}

	// Upsert a tenant via the registry directly; the stream must surface it.
	tenant := config.TenantConf{
		Host:    "live.example",
		Enabled: true,
		Backends: []config.BackendConf{
			{Addr: strings.Repeat("c", 56) + ".onion", Weight: 1},
		},
	}
	if err := f.reg.UpsertTenant(context.Background(), tenant); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	nextEvent, err := readSSEEvent(br, 1*time.Second)
	if err != nil {
		t.Fatalf("upsert event: %v", err)
	}
	if nextEvent.Type != shared.EventTenantUpsert {
		t.Fatalf("want tenant_upsert, got %q", nextEvent.Type)
	}
}

// TestAPI_ProxyTorpoolSuccess stands up a mock torpool listening on a Unix
// domain socket, points the hub at it, and verifies that /v1/backends is
// forwarded and the upstream response body passes through unchanged.
func TestAPI_ProxyTorpoolSuccess(t *testing.T) {
	if !SupportsUnixSockets() {
		t.Skip("unix sockets unsupported on this OS")
	}
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "torpool.sock")

	mock := http.NewServeMux()
	mock.HandleFunc("GET /backends", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"port":9050,"alive":true}]`))
	})
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Skipf("unix listen unsupported here: %v", err)
	}
	mockSrv := &http.Server{Handler: mock}
	go mockSrv.Serve(ln) //nolint:errcheck
	defer mockSrv.Close()

	f := newAPIFixtureWithSocket(t, sockPath)
	out, key := f.registerNode("edge-theta", "proxy")
	client := f.authClient(out.CertPEM, key)

	resp, err := client.Get(f.server.URL + "/v1/backends")
	if err != nil {
		t.Fatalf("backends: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("backends status %d: %s", resp.StatusCode, body)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"port":9050`) {
		t.Fatalf("unexpected backends body: %s", body)
	}
}

// TestAPI_ProxyTorpoolDisabled verifies that omitting the socket path makes
// the passthrough endpoints return a friendly 503 rather than a panic.
func TestAPI_ProxyTorpoolDisabled(t *testing.T) {
	f := newAPIFixture(t)
	out, key := f.registerNode("edge-iota", "proxy")
	client := f.authClient(out.CertPEM, key)

	resp, err := client.Get(f.server.URL + "/v1/backends")
	if err != nil {
		t.Fatalf("backends: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("want 503 with no socket, got %d", resp.StatusCode)
	}
}

// --- helpers ---

func newAPIFixtureWithSocket(t *testing.T, socketPath string) *apiFixture {
	t.Helper()
	dir := t.TempDir()
	reg, err := New(dir)
	if err != nil {
		t.Fatalf("new registry: %v", err)
	}
	t.Cleanup(func() { _ = reg.Close() })

	ca, err := NewCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("new ca: %v", err)
	}

	nodes := NewNodeStore()
	api := NewAPI(reg, ca, nodes, socketPath)

	serverCert := newServerCert(t, ca)

	srv := httptest.NewUnstartedServer(api.Handler())
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    ca.CertPool(),
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return &apiFixture{
		t:      t,
		dir:    dir,
		reg:    reg,
		ca:     ca,
		nodes:  nodes,
		api:    api,
		server: srv,
	}
}

func mustTLSCert(t *testing.T, certPEM string, key *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("decode client cert PEM")
	}
	return tls.Certificate{
		Certificate: [][]byte{block.Bytes},
		PrivateKey:  key,
	}
}

// readSSEEvent pulls one event: ...\ndata: ...\n\n block out of br and
// decodes the JSON body. deadline bounds the blocking read.
func readSSEEvent(br *bufio.Reader, deadline time.Duration) (shared.ConfigStreamEvent, error) {
	type result struct {
		ev  shared.ConfigStreamEvent
		err error
	}
	out := make(chan result, 1)
	go func() {
		var eventType, data string
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				out <- result{err: err}
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if line == "" {
				if data != "" {
					var ev shared.ConfigStreamEvent
					ev.Type = shared.ConfigStreamEventType(eventType)
					if err := json.Unmarshal([]byte(data), &ev); err != nil {
						out <- result{err: err}
						return
					}
					out <- result{ev: ev}
					return
				}
				continue
			}
			switch {
			case strings.HasPrefix(line, "event:"):
				eventType = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			case strings.HasPrefix(line, "data:"):
				data = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			}
		}
	}()
	select {
	case r := <-out:
		return r.ev, r.err
	case <-time.After(deadline):
		return shared.ConfigStreamEvent{}, context.DeadlineExceeded
	}
}

// collectingSub is a simple Subscriber that records events for assertions.
type collectingSub struct {
	mu     sync.Mutex
	events []shared.ConfigStreamEvent
	done   chan struct{}
	count  atomic.Int32
}

func (c *collectingSub) OnEvent(ev shared.ConfigStreamEvent) {
	c.mu.Lock()
	c.events = append(c.events, ev)
	c.mu.Unlock()
	c.count.Add(1)
	select {
	case c.done <- struct{}{}:
	default:
	}
}

func (c *collectingSub) lastType() shared.ConfigStreamEventType {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.events) == 0 {
		return ""
	}
	return c.events[len(c.events)-1].Type
}

// captureSlog redirects the default slog sink into a bytes.Buffer for the
// duration of the test. Used to assert that internal errors are recorded
// server-side even when the public body is redacted to a generic string.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	prev := slog.Default()
	buf := &bytes.Buffer{}
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

// TestAPI_UpsertTenantStorageErrorHidesPath forces a storage write failure
// by replacing the tenants/ directory with a regular file of the same
// name. The subsequent UpsertTenant must fail with a public body that
// contains no filesystem path while the underlying error remains in the
// captured slog output. Regression guard for OPSEC leak #1 on the hub
// admin API.
func TestAPI_UpsertTenantStorageErrorHidesPath(t *testing.T) {
	f := newAPIFixture(t)
	out, key := f.registerNode("edge-opsec", "proxy")
	client := f.authClient(out.CertPEM, key)

	// Sabotage the storage layer. NewStorage guarantees tenants/ exists;
	// removing it and creating a plain file in its place makes every
	// atomicWrite → MkdirAll fail with an OS-specific "not a directory"
	// error whose message contains the raw absolute filesystem path.
	tenantsPath := filepath.Join(f.dir, "tenants")
	if err := os.RemoveAll(tenantsPath); err != nil {
		t.Fatalf("remove tenants dir: %v", err)
	}
	if err := os.WriteFile(tenantsPath, []byte("sabotage"), 0o600); err != nil {
		t.Fatalf("replace tenants dir with file: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(tenantsPath) })

	buf := captureSlog(t)

	tenant := config.TenantConf{
		Host:    "leak.example",
		Enabled: true,
		Backends: []config.BackendConf{
			{Addr: strings.Repeat("f", 56) + ".onion", Weight: 1},
		},
	}
	body, _ := json.Marshal(tenant)
	req, _ := http.NewRequest(http.MethodPut,
		f.server.URL+"/v1/tenants/"+tenant.Host, bytes.NewReader(body))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.Fatalf("put unexpectedly succeeded; storage sabotage failed")
	}
	respBody, _ := io.ReadAll(resp.Body)

	// Public body must be the generic string — no filesystem path, no
	// wrapped os error.
	var pub struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(respBody, &pub); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if pub.Error == "" {
		t.Fatalf("empty error body: %q", respBody)
	}
	switch pub.Error {
	case "bad request", "internal error":
		// either is acceptable — UpsertTenant surfaces the write error
		// as 400 today, the helper would normalize either 400 or 500 to
		// a redacted body.
	default:
		t.Errorf("unexpected public error %q; want generic", pub.Error)
	}
	for _, leak := range []string{f.dir, tenantsPath, "leak.example.yaml", "mkdir", "rename"} {
		if strings.Contains(string(respBody), leak) {
			t.Errorf("public body leaks %q:\n%s", leak, respBody)
		}
	}

	// Internal slog capture must have recorded the original error so
	// operators can still debug.
	logged := buf.String()
	if !strings.Contains(logged, "hub api error") {
		t.Errorf("expected 'hub api error' slog record:\n%s", logged)
	}
	// Some signal that the real error was logged — the substring "hub
	// storage:" is present on every wrapped storage error.
	if !strings.Contains(logged, "hub storage:") {
		t.Errorf("expected underlying storage error in log:\n%s", logged)
	}
}

// TestAPI_BadJSONDoesNotLeakDecodeDetails verifies that a malformed JSON
// body on PUT /v1/tenants returns the fixed "bad request" public string
// rather than the json.Decoder's internal offset/character detail.
func TestAPI_BadJSONDoesNotLeakDecodeDetails(t *testing.T) {
	f := newAPIFixture(t)
	out, key := f.registerNode("edge-opsec-json", "proxy")
	client := f.authClient(out.CertPEM, key)

	buf := captureSlog(t)

	req, _ := http.NewRequest(http.MethodPut,
		f.server.URL+"/v1/tenants/foo.example",
		bytes.NewReader([]byte("{not-json")))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}
	respBody, _ := io.ReadAll(resp.Body)
	var pub struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(respBody, &pub); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if pub.Error != "bad request" {
		t.Errorf("public error = %q, want %q", pub.Error, "bad request")
	}
	// Specific json.Decoder error tokens that were previously echoed.
	for _, leak := range []string{"invalid character", "looking for beginning"} {
		if strings.Contains(string(respBody), leak) {
			t.Errorf("public body leaks decoder detail %q:\n%s", leak, respBody)
		}
	}
	if !strings.Contains(buf.String(), "hub api error") {
		t.Errorf("expected 'hub api error' in slog:\n%s", buf.String())
	}
}

// --- Mirror-health endpoint tests (P2) ---

// mirrorFixture extends apiFixture with a wired MirrorRegistry and an
// optional Monitor. Tests that need the mirror routes call newMirrorFixture
// instead of newAPIFixture so the /v1/mirrors handlers are not gated by the
// 503 "disabled" branch.
type mirrorFixture struct {
	*apiFixture
	mirrors *MirrorRegistry
	monitor *Monitor
	// checkCalls is incremented each time the fake monitor client's
	// CheckNow is invoked. Used by the POST /v1/mirrors/check test to
	// confirm the handler actually triggered CheckOnce.
	checkCalls *atomic.Int32
}

// fakeMonitorClient implements MonitorClient with a deterministic response
// and a call counter.
type fakeMonitorClient struct {
	calls *atomic.Int32
}

func (f *fakeMonitorClient) CheckNow(_ context.Context, _ string, _ []string, _ int, _ time.Duration, _ time.Duration) (map[string]NodeCheck, error) {
	if f.calls != nil {
		f.calls.Add(1)
	}
	return map[string]NodeCheck{
		"us1": {Status: "ok", LatencyMs: 42},
	}, nil
}

// newMirrorFixture builds the standard apiFixture and attaches a
// MirrorRegistry (disk-backed under the same temp dir) plus a Monitor
// whose client is the fake above. The monitor is not Start()-ed: tests
// use CheckOnce directly via the API surface.
func newMirrorFixture(t *testing.T) *mirrorFixture {
	t.Helper()
	base := newAPIFixture(t)

	reg, err := NewMirrors(base.dir)
	if err != nil {
		t.Fatalf("new mirrors: %v", err)
	}
	t.Cleanup(func() { _ = reg.Close() })

	var calls atomic.Int32
	mon := NewMonitor(reg, MonitorConfig{
		Enabled:  true,
		Client:   &fakeMonitorClient{calls: &calls},
		Interval: 1 * time.Hour,
		MaxNodes: 3,
		Poll:     10 * time.Millisecond,
		MaxWait:  100 * time.Millisecond,
	})

	base.api.WithMirrors(reg).WithMonitor(mon)

	return &mirrorFixture{
		apiFixture: base,
		mirrors:    reg,
		monitor:    mon,
		checkCalls: &calls,
	}
}

func TestAPI_ListMirrorsEmpty(t *testing.T) {
	f := newMirrorFixture(t)
	out, key := f.registerNode("edge-mirror-list", "proxy")
	client := f.authClient(out.CertPEM, key)

	resp, err := client.Get(f.server.URL + "/v1/mirrors")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var list []MirrorHealth
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("want empty list, got %+v", list)
	}
}

func TestAPI_PutAndGetMirror(t *testing.T) {
	f := newMirrorFixture(t)
	out, key := f.registerNode("edge-mirror-put", "proxy")
	client := f.authClient(out.CertPEM, key)

	mh := MirrorHealth{
		Host:    "m1.example",
		Verdict: VerdictLive,
		Weight:  2,
	}
	buf, _ := json.Marshal(mh)
	req, _ := http.NewRequest(http.MethodPut, f.server.URL+"/v1/mirrors/"+mh.Host, bytes.NewReader(buf))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("put status %d", resp.StatusCode)
	}

	// GET round-trips.
	g, err := client.Get(f.server.URL + "/v1/mirrors/" + mh.Host)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer g.Body.Close()
	if g.StatusCode != http.StatusOK {
		t.Fatalf("get status %d", g.StatusCode)
	}
	var got MirrorHealth
	if err := json.NewDecoder(g.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Host != mh.Host || got.Verdict != VerdictLive || got.Weight != 2 {
		t.Fatalf("unexpected mirror: %+v", got)
	}
}

func TestAPI_ForceBlockAndUnblockMirror(t *testing.T) {
	f := newMirrorFixture(t)
	out, key := f.registerNode("edge-mirror-block", "proxy")
	client := f.authClient(out.CertPEM, key)

	// Seed a mirror first.
	mh := MirrorHealth{Host: "m2.example", Verdict: VerdictLive, Weight: 1}
	body, _ := json.Marshal(mh)
	putReq, _ := http.NewRequest(http.MethodPut,
		f.server.URL+"/v1/mirrors/"+mh.Host, bytes.NewReader(body))
	if r, err := client.Do(putReq); err != nil {
		t.Fatalf("seed put: %v", err)
	} else {
		r.Body.Close()
	}

	// Force-block with a note.
	blockBody, _ := json.Marshal(forceBlockRequest{Note: "operator audit"})
	fbReq, _ := http.NewRequest(http.MethodPost,
		f.server.URL+"/v1/mirrors/"+mh.Host+"/force-block",
		bytes.NewReader(blockBody))
	fbReq.Header.Set("Content-Type", "application/json")
	fbResp, err := client.Do(fbReq)
	if err != nil {
		t.Fatalf("force-block: %v", err)
	}
	defer fbResp.Body.Close()
	if fbResp.StatusCode != http.StatusOK {
		t.Fatalf("force-block status %d", fbResp.StatusCode)
	}
	var blocked MirrorHealth
	if err := json.NewDecoder(fbResp.Body).Decode(&blocked); err != nil {
		t.Fatalf("decode block: %v", err)
	}
	if !blocked.ManualBlock || blocked.ManualNote != "operator audit" {
		t.Fatalf("unexpected force-block state: %+v", blocked)
	}
	if blocked.Verdict != VerdictBlocked {
		t.Fatalf("force-block verdict = %q, want blocked", blocked.Verdict)
	}

	// Unblock clears both flag and note.
	ubReq, _ := http.NewRequest(http.MethodPost,
		f.server.URL+"/v1/mirrors/"+mh.Host+"/unblock", nil)
	ubResp, err := client.Do(ubReq)
	if err != nil {
		t.Fatalf("unblock: %v", err)
	}
	defer ubResp.Body.Close()
	if ubResp.StatusCode != http.StatusOK {
		t.Fatalf("unblock status %d", ubResp.StatusCode)
	}
	var unblocked MirrorHealth
	if err := json.NewDecoder(ubResp.Body).Decode(&unblocked); err != nil {
		t.Fatalf("decode unblock: %v", err)
	}
	if unblocked.ManualBlock || unblocked.ManualNote != "" {
		t.Fatalf("unblock left state: %+v", unblocked)
	}
}

func TestAPI_DeleteMirror(t *testing.T) {
	f := newMirrorFixture(t)
	out, key := f.registerNode("edge-mirror-del", "proxy")
	client := f.authClient(out.CertPEM, key)

	mh := MirrorHealth{Host: "m3.example", Verdict: VerdictLive}
	body, _ := json.Marshal(mh)
	putReq, _ := http.NewRequest(http.MethodPut,
		f.server.URL+"/v1/mirrors/"+mh.Host, bytes.NewReader(body))
	if r, err := client.Do(putReq); err != nil {
		t.Fatalf("put: %v", err)
	} else {
		r.Body.Close()
	}

	delReq, _ := http.NewRequest(http.MethodDelete,
		f.server.URL+"/v1/mirrors/"+mh.Host, nil)
	delResp, err := client.Do(delReq)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status %d", delResp.StatusCode)
	}

	g, err := client.Get(f.server.URL + "/v1/mirrors/" + mh.Host)
	if err != nil {
		t.Fatalf("get-after-delete: %v", err)
	}
	defer g.Body.Close()
	if g.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404 after delete, got %d", g.StatusCode)
	}
}

func TestAPI_PostMirrorsCheckTriggersMonitor(t *testing.T) {
	f := newMirrorFixture(t)
	out, key := f.registerNode("edge-mirror-check", "proxy")
	client := f.authClient(out.CertPEM, key)

	// Seed at least one mirror so CheckOnce has something to probe.
	mh := MirrorHealth{Host: "m4.example", Verdict: VerdictUnknown}
	body, _ := json.Marshal(mh)
	putReq, _ := http.NewRequest(http.MethodPut,
		f.server.URL+"/v1/mirrors/"+mh.Host, bytes.NewReader(body))
	if r, err := client.Do(putReq); err != nil {
		t.Fatalf("put: %v", err)
	} else {
		r.Body.Close()
	}

	before := f.checkCalls.Load()
	checkReq, _ := http.NewRequest(http.MethodPost,
		f.server.URL+"/v1/mirrors/check",
		bytes.NewReader([]byte(`{"regions":["us1"]}`)))
	checkReq.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(checkReq)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("check status %d: %s", resp.StatusCode, b)
	}
	if got := f.checkCalls.Load(); got <= before {
		t.Fatalf("CheckNow not invoked: before=%d after=%d", before, got)
	}
}

func TestAPI_GetCheckHostSettingsDefaultsOnFreshInstall(t *testing.T) {
	f := newMirrorFixture(t)
	out, key := f.registerNode("edge-settings-get", "proxy")
	client := f.authClient(out.CertPEM, key)

	resp, err := client.Get(f.server.URL + "/v1/settings/checkhost")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var s CheckHostSettings
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Fresh install: LoadCheckHostSettings returns the zero value when the
	// file is missing. We only assert the call succeeded and JSON decoded;
	// specific default values live in the Monitor's resolveSettings, not
	// on disk.
	if s.MaxNodes != 0 || s.Enabled != false || len(s.Regions) != 0 {
		// Non-zero values mean the file existed when we didn't expect it.
		t.Fatalf("expected zero-value settings on fresh install, got %+v", s)
	}
}

func TestAPI_PutCheckHostSettingsPersists(t *testing.T) {
	f := newMirrorFixture(t)
	out, key := f.registerNode("edge-settings-put", "proxy")
	client := f.authClient(out.CertPEM, key)

	want := CheckHostSettings{
		Enabled:      true,
		Interval:     5 * time.Minute,
		Regions:      []string{"us1", "de1"},
		MaxNodes:     4,
		ThresholdPct: 0.5,
	}
	body, _ := json.Marshal(want)
	putReq, _ := http.NewRequest(http.MethodPut,
		f.server.URL+"/v1/settings/checkhost", bytes.NewReader(body))
	resp, err := client.Do(putReq)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("put status %d", resp.StatusCode)
	}

	// Subsequent GET returns what we wrote.
	g, err := client.Get(f.server.URL + "/v1/settings/checkhost")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer g.Body.Close()
	var got CheckHostSettings
	if err := json.NewDecoder(g.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Enabled != want.Enabled || got.Interval != want.Interval ||
		got.MaxNodes != want.MaxNodes || got.ThresholdPct != want.ThresholdPct ||
		len(got.Regions) != len(want.Regions) {
		t.Fatalf("round-trip mismatch: got %+v want %+v", got, want)
	}

	// And the file physically exists under the expected path.
	if _, err := os.Stat(filepath.Join(f.dir, "runtime", "settings", "checkhost.yaml")); err != nil {
		t.Fatalf("settings file missing: %v", err)
	}
}

func TestAPI_MirrorEndpointsRequireMTLS(t *testing.T) {
	f := newMirrorFixture(t)

	resp, err := f.plainClient().Get(f.server.URL + "/v1/mirrors")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
}

// TestAPI_StreamReceivesMirrorUpsert drives a PUT against /v1/mirrors/{host}
// and verifies a matching mirror_upsert event arrives on the SSE stream.
// Only the event type is asserted here; payload shape is covered by
// mirrors_test.go on the registry side.
func TestAPI_StreamReceivesMirrorUpsert(t *testing.T) {
	f := newMirrorFixture(t)
	out, key := f.registerNode("edge-mirror-sse", "proxy")

	// Raw TLS dialer so we can read SSE line-by-line.
	dialer := &tls.Dialer{
		Config: &tls.Config{
			RootCAs:      f.ca.CertPool(),
			Certificates: []tls.Certificate{mustTLSCert(t, out.CertPEM, key)},
			ServerName:   "hub.test",
			MinVersion:   tls.VersionTLS12,
		},
	}
	host := strings.TrimPrefix(f.server.URL, "https://")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	req, _ := http.NewRequest(http.MethodGet,
		f.server.URL+"/v1/config/stream", nil)
	if err := req.Write(conn); err != nil {
		t.Fatalf("write req: %v", err)
	}

	br := bufio.NewReader(conn)
	// Skip HTTP status + headers.
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatalf("status line: %v", err)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("header read: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	// The first two events are the tenant snapshot and the mirror snapshot
	// (in some order). Drain them so we are aligned on the next delta.
	for i := 0; i < 2; i++ {
		if _, err := readSSEEvent(br, 2*time.Second); err != nil {
			t.Fatalf("initial event %d: %v", i, err)
		}
	}

	// Perform the upsert via the registry (equivalent to PUT /v1/mirrors
	// from the handler layer's perspective — same broadcast path).
	mh := MirrorHealth{Host: "sse.example", Verdict: VerdictLive, Weight: 1}
	if err := f.mirrors.Upsert(context.Background(), mh); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	ev, err := readSSEEvent(br, 2*time.Second)
	if err != nil {
		t.Fatalf("upsert event: %v", err)
	}
	if ev.Type != shared.EventMirrorUpsert {
		t.Fatalf("want mirror_upsert, got %q", ev.Type)
	}
}
