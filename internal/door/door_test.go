package door

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gateway/internal/admin"
	"gateway/internal/config"
	"gateway/internal/shared"
)

func buildTestServer(t *testing.T, gateCfg admin.Config) (*Server, *Selector, string) {
	t.Helper()
	coverPath := filepath.Join(t.TempDir(), "cover.html")
	if err := os.WriteFile(coverPath, []byte("<html>ok</html>"), 0o600); err != nil {
		t.Fatalf("write cover: %v", err)
	}
	sel := NewSelector()
	sel.UpdateMirrors([]shared.MirrorInfo{
		{Host: "mirror-a.example", Verdict: "live"},
	})
	cfg := &config.Config{
		Door: config.DoorConf{
			Cover: config.CoverConf{
				Enabled: true,
				Kind:    config.CoverKindStaticHTML,
				Path:    coverPath,
			},
			Slugs: []config.SlugConf{
				{Slug: "slugslugslugslugslugslugslugslug", Strategy: config.StrategyRandom, Status: 302},
			},
		},
	}
	gate := admin.New(gateCfg)
	srv, err := NewServer(cfg, sel, gate, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv, sel, "slugslugslugslugslugslugslugslug"
}

func TestServer_GetRootServesCover(t *testing.T) {
	srv, _, _ := buildTestServer(t, admin.Config{})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "<html>ok</html>") {
		t.Fatalf("cover body mismatch: %q", body)
	}
}

func TestServer_GetSlugRedirects(t *testing.T) {
	srv, _, slug := buildTestServer(t, admin.Config{})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/"+slug+"/deep?q=1", nil))
	resp := rec.Result()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	want := "https://mirror-a.example/deep?q=1"
	if loc != want {
		t.Errorf("Location = %q, want %q", loc, want)
	}
}

func TestServer_GetUnknownPathFallsToCover(t *testing.T) {
	srv, _, _ := buildTestServer(t, admin.Config{})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/totally-random-path", nil))
	// Unknown paths fall through to the cover → 200 with cover body.
	if rec.Code != http.StatusOK {
		t.Fatalf("unknown path status = %d, want 200 (cover)", rec.Code)
	}
}

func TestServer_HeadReturns200Empty(t *testing.T) {
	srv, _, slug := buildTestServer(t, admin.Config{})
	// HEAD on both root and the slug path.
	for _, p := range []string{"/", "/" + slug, "/unknown"} {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, p, nil))
		resp := rec.Result()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("HEAD %s status = %d", p, resp.StatusCode)
		}
		if len(body) != 0 {
			t.Errorf("HEAD %s body = %q", p, body)
		}
	}
}

func TestServer_PostReturns405(t *testing.T) {
	srv, _, slug := buildTestServer(t, admin.Config{})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/"+slug, nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", rec.Code)
	}
}

func TestServer_AdminGatePath(t *testing.T) {
	gateCfg := admin.Config{
		Enabled: true,
		Slug:    strings.Repeat("a", 32),
		Token1:  strings.Repeat("b", 32),
		Token2:  strings.Repeat("c", 32),
	}
	srv, _, _ := buildTestServer(t, gateCfg)

	// Correct triplet → 501 Not Implemented (admin P1 stub).
	rec := httptest.NewRecorder()
	path := "/" + gateCfg.Slug + "/" + gateCfg.Token1 + "/" + gateCfg.Token2
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("admin triplet status = %d, want 501", rec.Code)
	}

	// Wrong triplet → indistinguishable from a plain unknown path. The
	// constant-time gate does not trigger, so the outer router falls
	// through to the cover handler (200 with cover body). The
	// important property is that nothing on the wire reveals whether
	// the slug/token1/token2 partially matched.
	rec2 := httptest.NewRecorder()
	bad := "/" + gateCfg.Slug + "/" + strings.Repeat("x", 32) + "/" + gateCfg.Token2
	srv.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, bad, nil))
	if rec2.Code == http.StatusNotImplemented {
		t.Fatalf("bad admin triplet leaked 501")
	}
}

func TestServer_RejectsNilConfig(t *testing.T) {
	if _, err := NewServer(nil, NewSelector(), nil, nil); err == nil {
		t.Fatal("expected error on nil config")
	}
}

func TestServer_RejectsNilSelector(t *testing.T) {
	if _, err := NewServer(&config.Config{}, nil, nil, nil); err == nil {
		t.Fatal("expected error on nil selector")
	}
}

func TestServer_UpdateSlugs_HotReload(t *testing.T) {
	srv, _, _ := buildTestServer(t, admin.Config{})
	srv.UpdateSlugs([]config.SlugConf{
		{Slug: "newnewnewnewnewnewnewnewnewnewne", Strategy: config.StrategyRandom, Status: 302},
	})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/newnewnewnewnewnewnewnewnewnewne", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("hot-reloaded slug not active: status %d", rec.Code)
	}
}

// ---------- snapshot.go ----------

// sseServer is a minimal httptest server that streams preset events
// and keeps the connection open until ctx fires so the client's drain
// loop can observe them in order.
func sseServer(t *testing.T, events []shared.ConfigStreamEvent) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "no flusher", 500)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		for _, ev := range events {
			payload, _ := json.Marshal(ev)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, payload)
			flusher.Flush()
		}
		<-r.Context().Done()
	}))
}

func TestSnapshotClient_InitialSnapshotUpdatesSelector(t *testing.T) {
	ev, err := shared.NewMirrorSnapshotEvent([]shared.MirrorInfo{
		{Host: "m1.example", Verdict: "live"},
		{Host: "m2.example", Verdict: "blocked"},
	}, 1)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	server := sseServer(t, []shared.ConfigStreamEvent{ev})
	defer server.Close()

	sel := NewSelector()
	cfg := &config.Config{HubURL: server.URL}
	client := NewSnapshotClient(cfg, nil, sel)
	client.minBackoff = 10 * time.Millisecond
	client.maxBackoff = 50 * time.Millisecond
	client.initialTimeout = 2 * time.Second

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); client.Close() })

	if err := client.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Wait for the selector to be populated.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(sel.Mirrors()) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	ms := sel.Mirrors()
	if len(ms) != 2 {
		t.Fatalf("expected 2 mirrors, got %d: %+v", len(ms), ms)
	}
}

func TestSnapshotClient_UpsertAndDelete(t *testing.T) {
	evSnap, _ := shared.NewMirrorSnapshotEvent(nil, 1)
	evUp, _ := shared.NewMirrorUpsertEvent(shared.MirrorInfo{Host: "x.example", Verdict: "live"})
	evDel, _ := shared.NewMirrorDeleteEvent("x.example")

	server := sseServer(t, []shared.ConfigStreamEvent{evSnap, evUp, evDel})
	defer server.Close()

	sel := NewSelector()
	cfg := &config.Config{HubURL: server.URL}
	client := NewSnapshotClient(cfg, nil, sel)
	client.minBackoff = 10 * time.Millisecond
	client.maxBackoff = 50 * time.Millisecond
	client.initialTimeout = 2 * time.Second

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); client.Close() })

	if err := client.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Wait for the delete to land. The delete removes x.example, so
	// the selector should eventually be empty.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(sel.Mirrors()) == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("mirror still present after delete: %+v", sel.Mirrors())
}

func TestSnapshotClient_StartFailsOnUnreachable(t *testing.T) {
	sel := NewSelector()
	// Pointing at a bogus URL should fail fast rather than hang the
	// bootstrap.
	cfg := &config.Config{HubURL: "http://127.0.0.1:1"}
	client := NewSnapshotClient(cfg, nil, sel)
	client.initialTimeout = 200 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := client.Start(ctx)
	if err == nil {
		t.Fatal("expected error on unreachable hub")
	}
}

// TestSnapshotClient_Non200Fails ensures a non-200 SSE response is
// translated into a Start error rather than spinning the reconnect
// loop silently.
func TestSnapshotClient_Non200Fails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer server.Close()
	sel := NewSelector()
	cfg := &config.Config{HubURL: server.URL}
	client := NewSnapshotClient(cfg, nil, sel)
	client.initialTimeout = 500 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Start(ctx); err == nil {
		t.Fatal("expected error on 403 hub")
	}
}

// parseSSE-level smoke test: feed a hand-crafted SSE stream and ensure
// events land in order.
func TestParseSSE_ReadsEventsInOrder(t *testing.T) {
	raw := "event: mirror_snapshot\n" +
		`data: {"type":"mirror_snapshot","data":{"mirrors":[],"version":1}}` + "\n\n" +
		"event: mirror_upsert\n" +
		`data: {"type":"mirror_upsert","data":{"host":"h","verdict":"live"}}` + "\n\n"
	var (
		mu     sync.Mutex
		types  []shared.ConfigStreamEventType
	)
	onEvent := func(ev shared.ConfigStreamEvent) {
		mu.Lock()
		types = append(types, ev.Type)
		mu.Unlock()
	}
	if err := parseSSE(context.Background(), bufio.NewReader(strings.NewReader(raw)), onEvent, -1); err != nil {
		t.Fatalf("parseSSE: %v", err)
	}
	if len(types) != 2 || types[0] != shared.EventMirrorSnapshot || types[1] != shared.EventMirrorUpsert {
		t.Fatalf("unexpected events: %v", types)
	}
}
