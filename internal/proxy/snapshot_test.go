package proxy

import (
	"context"
	"encoding/json"
	"fmt"
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
	"gateway/internal/feature"
	"gateway/internal/shared"
)

// recordingFeature is a feature.Feature used by snapshot_test to watch
// for Reload events without pulling in a heavy real feature.
type recordingFeature struct {
	name     string
	mu       sync.Mutex
	reloads  int
	lastSnap shared.FeatureSnapshot
}

func newRecordingFeature(name string) *recordingFeature {
	return &recordingFeature{name: name}
}

func (f *recordingFeature) Name() string { return f.name }

func (f *recordingFeature) Middleware(_ feature.Resolver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler { return next }
}

func (f *recordingFeature) Validate(_ shared.FeatureSnapshot) error { return nil }

func (f *recordingFeature) observe(snap shared.FeatureSnapshot) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reloads++
	f.lastSnap = snap
}

func (f *recordingFeature) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reloads
}

func (f *recordingFeature) snapshot() shared.FeatureSnapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastSnap
}

// writeGlobalsFile writes a valid globals.yaml into dir.
func writeGlobalsFile(t *testing.T, dir string, enabled bool) {
	t.Helper()
	payload := fmt.Sprintf(`
features:
  recording:
    enabled: %t
    params:
      example: "value"
block_response:
  default: 404
`, enabled)
	if err := os.WriteFile(filepath.Join(dir, "globals.yaml"), []byte(payload), 0o600); err != nil {
		t.Fatalf("write globals: %v", err)
	}
}

// writeTenantFile writes a tenant YAML into dir/tenants/<host>.yaml.
func writeTenantFile(t *testing.T, dir, host string, enabled bool) {
	t.Helper()
	payload := fmt.Sprintf(`
host: %s
enabled: %t
backends:
  - addr: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad.onion
    weight: 1
`, host, enabled)
	if err := os.WriteFile(filepath.Join(dir, "tenants", host+".yaml"), []byte(payload), 0o600); err != nil {
		t.Fatalf("write tenant %s: %v", host, err)
	}
}

func TestLocalClient_InitialLoadAndFSNotifyPicksUpChanges(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "tenants"), 0o755); err != nil {
		t.Fatalf("mkdir tenants: %v", err)
	}
	writeGlobalsFile(t, dir, true)
	writeTenantFile(t, dir, "a.example", true)

	reg := feature.NewRegistry()
	rec := newRecordingFeature("recording")
	reg.Register(rec)
	reg.AddReloadObserver(rec.Name(), rec.observe)

	cfg := &config.Config{Mode: config.ModeLocal, Hub: config.HubConf{DataDir: dir}}

	client := NewLocalClient(cfg, reg)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = client.Close() })

	if err := client.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Initial tenant should be present after Start returned.
	tenants := reg.Tenants()
	if _, ok := tenants["a.example"]; !ok {
		t.Fatalf("expected tenant a.example after initial load; got %v", tenants)
	}

	// Now add a second tenant on disk and wait for the fsnotify-driven
	// reload to land.
	writeTenantFile(t, dir, "b.example", true)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		tenants := reg.Tenants()
		if _, ok := tenants["b.example"]; ok {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("b.example never appeared in registry; current: %v", reg.Tenants())
}

func TestLocalClient_NoDataDirIsNoop(t *testing.T) {
	reg := feature.NewRegistry()
	cfg := &config.Config{Mode: config.ModeLocal}
	client := NewLocalClient(cfg, reg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := client.Start(ctx); err != nil {
		t.Fatalf("Start with empty DataDir should be a no-op, got %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestNewSnapshotClient_NilRegistryReturnsNoop(t *testing.T) {
	c := NewSnapshotClient(&config.Config{Mode: config.ModeLocal}, nil, nil)
	if _, ok := c.(*noopClient); !ok {
		t.Fatalf("expected noopClient, got %T", c)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("noop Start: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("noop Close: %v", err)
	}
}

func TestTranslateEvent_TenantUpsert(t *testing.T) {
	prevG := feature.GlobalsSnapshot{Features: map[string]shared.FeatureSnapshot{}}
	prevT := map[string]feature.TenantSnapshot{}

	ti := shared.TenantInfo{
		Host:    "new.example",
		Enabled: true,
		FeatureSnapshots: map[string]shared.FeatureSnapshot{
			"recording": {Enabled: true},
		},
	}
	raw, err := json.Marshal(ti)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	ev := shared.ConfigStreamEvent{Type: shared.EventTenantUpsert, Data: raw}

	gotG, gotT, err := translateEvent(ev, prevG, prevT)
	if err != nil {
		t.Fatalf("translateEvent: %v", err)
	}
	if gotG.Features == nil {
		t.Fatal("expected globals features map to be non-nil")
	}
	if _, ok := gotT["new.example"]; !ok {
		t.Fatalf("expected new.example tenant; got %v", gotT)
	}
	tenant := gotT["new.example"]
	if !tenant.Enabled {
		t.Fatal("tenant should be enabled")
	}
	if fs, ok := tenant.Features["recording"]; !ok || !fs.Enabled {
		t.Fatalf("expected recording feature enabled on tenant; got %+v", tenant.Features)
	}
}

func TestTranslateEvent_TenantDelete(t *testing.T) {
	prevG := feature.GlobalsSnapshot{Features: map[string]shared.FeatureSnapshot{}}
	prevT := map[string]feature.TenantSnapshot{
		"gone.example": {Host: "gone.example", Enabled: true},
	}

	payload := shared.TenantDeletePayload{Host: "gone.example"}
	raw, _ := json.Marshal(payload)
	ev := shared.ConfigStreamEvent{Type: shared.EventTenantDelete, Data: raw}

	_, gotT, err := translateEvent(ev, prevG, prevT)
	if err != nil {
		t.Fatalf("translateEvent: %v", err)
	}
	if _, ok := gotT["gone.example"]; ok {
		t.Fatalf("expected tenant removed; still present: %v", gotT)
	}
}

func TestTranslateEvent_Snapshot(t *testing.T) {
	prevG := feature.GlobalsSnapshot{Features: map[string]shared.FeatureSnapshot{}}
	prevT := map[string]feature.TenantSnapshot{}

	gJSON, _ := json.Marshal(config.GlobalsConf{Features: map[string]config.FeatureConf{
		"recording": {Enabled: true, Params: map[string]any{"k": "v"}},
	}})
	payload := shared.SnapshotPayload{
		Tenants: []shared.TenantInfo{
			{Host: "x.example", Enabled: true},
			{Host: "y.example", Enabled: false},
		},
		Globals: gJSON,
	}
	raw, _ := json.Marshal(payload)
	ev := shared.ConfigStreamEvent{Type: shared.EventSnapshot, Data: raw}

	gotG, gotT, err := translateEvent(ev, prevG, prevT)
	if err != nil {
		t.Fatalf("translateEvent: %v", err)
	}
	if fs, ok := gotG.Features["recording"]; !ok || !fs.Enabled {
		t.Fatalf("expected recording globals, got %+v", gotG.Features)
	}
	if len(gotT) != 2 {
		t.Fatalf("expected 2 tenants, got %d", len(gotT))
	}
}

func TestParseSSEStream_ReadsFrames(t *testing.T) {
	body := "event: globals_update\n" +
		"data: " + `{"type":"globals_update","data":{"features":{"recording":{"enabled":true}}},"timestamp":"2024-01-01T00:00:00Z"}` + "\n\n" +
		"event: tenant_delete\n" +
		"data: " + `{"type":"tenant_delete","data":{"host":"d.example"},"timestamp":"2024-01-01T00:00:00Z"}` + "\n\n"

	var got []shared.ConfigStreamEvent
	err := parseSSEStream(context.Background(), strings.NewReader(body), func(ev shared.ConfigStreamEvent) {
		got = append(got, ev)
	})
	if err != nil {
		t.Fatalf("parseSSEStream: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 events, got %d (%v)", len(got), got)
	}
	if got[0].Type != shared.EventGlobalsUpdate {
		t.Errorf("first event type = %v", got[0].Type)
	}
	if got[1].Type != shared.EventTenantDelete {
		t.Errorf("second event type = %v", got[1].Type)
	}
}

// TestRemoteClient_ReconnectsWithBackoff is the end-to-end exercise of
// the remote client: the first connection succeeds synchronously (so
// Start returns nil with the registry already populated), then the
// hub repeatedly closes the stream after one frame and the client
// reconnects with exponential backoff.
func TestRemoteClient_ReconnectsWithBackoff(t *testing.T) {
	var connects atomic.Int32

	// The test server accepts an SSE connection, writes a snapshot,
	// closes the connection, and repeats on subsequent requests. This
	// simulates the hub closing the stream so the client's reconnect
	// loop is exercised.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connects.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		// Emit one snapshot event and return immediately so the client
		// sees the body closed.
		payload := shared.SnapshotPayload{Version: uint64(connects.Load())}
		raw, _ := json.Marshal(payload)
		ev := shared.ConfigStreamEvent{Type: shared.EventSnapshot, Data: raw}
		frameJSON, _ := json.Marshal(ev)
		fmt.Fprintf(w, "event: snapshot\ndata: %s\n\n", string(frameJSON))
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}))
	defer srv.Close()

	cfg := &config.Config{Mode: config.ModeRemote, HubURL: srv.URL}
	reg := feature.NewRegistry()
	rec := newRecordingFeature("recording")
	reg.Register(rec)
	reg.AddReloadObserver(rec.Name(), rec.observe)

	client := NewRemoteClient(cfg, nil, reg)
	client.minBackoff = 10 * time.Millisecond
	client.maxBackoff = 20 * time.Millisecond
	client.initialTimeout = 2 * time.Second
	client.SetStreamURL(srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	if err := client.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Start completes synchronously once the first snapshot has been
	// consumed, so at this point connects must already be >= 1.
	if connects.Load() < 1 {
		t.Fatalf("expected Start to have connected, got connects=%d", connects.Load())
	}
	// Wait until at least 3 reconnect attempts have happened so we know
	// the backoff loop is active.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if connects.Load() >= 3 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	_ = client.Close()

	if connects.Load() < 2 {
		t.Fatalf("expected multiple connect attempts, got %d", connects.Load())
	}
}

// TestRemoteClient_StartReturnsErrorIfHubUnreachable confirms the
// blocking-first-attempt contract: when the hub does not respond,
// Start returns the transport error and leaves no goroutine running.
func TestRemoteClient_StartReturnsErrorIfHubUnreachable(t *testing.T) {
	// Bind a listener and close it immediately to guarantee the
	// address is unreachable without racing on port reuse.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	cfg := &config.Config{Mode: config.ModeRemote, HubURL: "http://" + addr}
	reg := feature.NewRegistry()

	client := NewRemoteClient(cfg, nil, reg)
	client.minBackoff = 10 * time.Millisecond
	client.maxBackoff = 20 * time.Millisecond
	client.initialTimeout = 300 * time.Millisecond
	client.SetStreamURL("http://" + addr + "/v1/config/stream")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = client.Start(ctx)
	if err == nil {
		_ = client.Close()
		t.Fatal("Start must return error when hub is unreachable")
	}

	// A failed Start must NOT spawn the reconnect goroutine: there is
	// nothing to Close, but calling Close anyway must remain safe.
	if cerr := client.Close(); cerr != nil {
		t.Fatalf("Close after failed Start returned %v", cerr)
	}
}

func TestTranslateGlobalsRaw_FallsBackGracefully(t *testing.T) {
	// Empty raw produces an empty but non-nil features map.
	out := translateGlobalsRaw(nil)
	if out.Features == nil {
		t.Fatal("expected non-nil features map")
	}
	if len(out.Features) != 0 {
		t.Fatalf("expected empty features, got %v", out.Features)
	}

	// Bogus JSON falls back to zero value.
	out = translateGlobalsRaw([]byte(`not-json`))
	if out.Features == nil {
		t.Fatal("expected non-nil features map on bogus input")
	}
}
