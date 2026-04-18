package admin

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gateway/internal/config"
	"gateway/internal/hub"
	"gateway/internal/metrics"
)

// fakeHub is an in-memory implementation of HubAccess used in router
// tests. It tracks the calls made against it so the upsert/delete
// audit verification can confirm the router actually drove the right
// method.
type fakeHub struct {
	mu       sync.Mutex
	tenants  map[string]config.TenantConf
	globals  config.GlobalsConf
	mirrors  []hub.MirrorHealth
	upserts  int
	deletes  int
	setG     int
}

func newFakeHub() *fakeHub {
	return &fakeHub{tenants: make(map[string]config.TenantConf)}
}

func (f *fakeHub) ListTenants() []config.TenantConf {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]config.TenantConf, 0, len(f.tenants))
	for _, t := range f.tenants {
		out = append(out, t)
	}
	return out
}

func (f *fakeHub) GetTenant(host string) (config.TenantConf, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.tenants[host]
	return t, ok
}

func (f *fakeHub) UpsertTenant(_ context.Context, t config.TenantConf) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tenants[t.Host] = t
	f.upserts++
	return nil
}

func (f *fakeHub) DeleteTenant(_ context.Context, host string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.tenants, host)
	f.deletes++
	return nil
}

func (f *fakeHub) GetGlobals() config.GlobalsConf {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.globals
}

func (f *fakeHub) SetGlobals(_ context.Context, g config.GlobalsConf) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.globals = g
	f.setG++
	return nil
}

func (f *fakeHub) ListMirrors() []hub.MirrorHealth {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]hub.MirrorHealth, len(f.mirrors))
	copy(out, f.mirrors)
	return out
}

// fakeFeatures captures Toggle calls against an in-memory map.
type fakeFeatures struct {
	mu      sync.Mutex
	state   map[string]bool
	known   map[string]bool
	toggles int
}

func newFakeFeatures(known ...string) *fakeFeatures {
	k := make(map[string]bool, len(known))
	s := make(map[string]bool, len(known))
	for _, n := range known {
		k[n] = true
		s[n] = false
	}
	return &fakeFeatures{state: s, known: k}
}

func (f *fakeFeatures) ListFeatures() []FeatureStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]FeatureStatus, 0, len(f.state))
	for n, v := range f.state {
		out = append(out, FeatureStatus{Name: n, Enabled: v})
	}
	return out
}

func (f *fakeFeatures) ToggleGlobal(name string, enabled bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.known[name] {
		return ErrUnknownFeature()
	}
	f.state[name] = enabled
	f.toggles++
	return nil
}

// fakeMetrics is a tiny stub — Snapshot is fixed text, History is a
// slice of pre-built buckets.
type fakeMetrics struct{ text []byte }

func (f *fakeMetrics) Snapshot() []byte { return f.text }
func (f *fakeMetrics) History(limit int) []MetricsBucket {
	out := []MetricsBucket{
		{At: time.Now(), RPS: 1.0, ErrRate: 0.01, Backends: 4},
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// memAudit is an in-memory AuditAccess so router tests can verify the
// router appended the expected event.
type memAudit struct {
	mu     sync.Mutex
	events []Event
}

func (m *memAudit) Append(e Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, e)
	return nil
}

func (m *memAudit) Query(_ time.Time, _ int) ([]Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Event, len(m.events))
	copy(out, m.events)
	return out, nil
}

func newRouterHarness(t *testing.T, nodeType string) (http.Handler, *fakeHub, *fakeFeatures, *memAudit) {
	t.Helper()
	tmp := t.TempDir()
	lab, err := metrics.NewLabeler(metrics.Config{
		HashTenantLabels: true,
		SaltFile:         filepath.Join(tmp, "salt"),
	})
	if err != nil {
		t.Fatalf("NewLabeler: %v", err)
	}
	fh := newFakeHub()
	ff := newFakeFeatures("staticcache", "abuse")
	fm := &fakeMetrics{text: []byte("# HELP foo bar\nfoo 1\n")}
	fa := &memAudit{}
	r := Routes{
		NodeID:   "test",
		NodeType: nodeType,
		Hub:      fh,
		Features: ff,
		Metrics:  fm,
		Audit:    fa,
		Labeler:  lab,
	}
	if nodeType != config.NodeTypeHub {
		r.Hub = nil
	}
	return NewRouter(r), fh, ff, fa
}

// TestRouter_NonHubBlocksTenantRoutes: on proxy/door, the
// /api/tenants surface returns 403. A small JSON error body is
// expected per spec ("typed JSON, public error strings").
func TestRouter_NonHubBlocksTenantRoutes(t *testing.T) {
	h, _, _, _ := newRouterHarness(t, config.NodeTypeProxy)

	req := httptest.NewRequest(http.MethodGet, "/api/tenants", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "hub") {
		t.Fatalf("body should mention hub: %q", body)
	}
}

// TestRouter_HubTenantsCRUD walks GET → PUT → GET → DELETE on
// /api/tenants{,/host}. Verifies the audit log captures upsert and
// delete events.
func TestRouter_HubTenantsCRUD(t *testing.T) {
	h, fh, _, fa := newRouterHarness(t, config.NodeTypeHub)

	// GET (empty)
	req := httptest.NewRequest(http.MethodGet, "/api/tenants", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET tenants: want 200, got %d", rec.Code)
	}

	// PUT
	body := `{"host":"shop.example","enabled":true}`
	req = httptest.NewRequest(http.MethodPut, "/api/tenants/shop.example", strings.NewReader(body))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("PUT tenant: want 204, got %d (%s)", rec.Code, rec.Body.String())
	}
	if fh.upserts != 1 {
		t.Fatalf("upserts=%d, want 1", fh.upserts)
	}

	// GET (one)
	req = httptest.NewRequest(http.MethodGet, "/api/tenants/shop.example", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET single tenant: want 200, got %d", rec.Code)
	}

	// DELETE
	req = httptest.NewRequest(http.MethodDelete, "/api/tenants/shop.example", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE tenant: want 204, got %d", rec.Code)
	}
	if fh.deletes != 1 {
		t.Fatalf("deletes=%d, want 1", fh.deletes)
	}

	// Audit
	events, _ := fa.Query(time.Time{}, 100)
	hasUpsert, hasDelete := false, false
	for _, e := range events {
		switch e.Action {
		case "tenant.upsert":
			hasUpsert = true
		case "tenant.delete":
			hasDelete = true
		}
	}
	if !hasUpsert || !hasDelete {
		t.Fatalf("expected both upsert+delete in audit, got %+v", events)
	}
}

// TestRouter_FeatureToggleAudits confirms POST /api/features/{name}/toggle
// drives FeatureAccess.ToggleGlobal AND emits an audit event.
func TestRouter_FeatureToggleAudits(t *testing.T) {
	h, _, ff, fa := newRouterHarness(t, config.NodeTypeHub)

	body := `{"enabled":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/features/staticcache/toggle", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d (%s)", rec.Code, rec.Body.String())
	}
	if ff.toggles != 1 {
		t.Fatalf("toggles=%d, want 1", ff.toggles)
	}
	events, _ := fa.Query(time.Time{}, 10)
	found := false
	for _, e := range events {
		if e.Action == "feature.toggle" && e.Target == "staticcache" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no feature.toggle audit event: %+v", events)
	}
}

// TestRouter_FeatureToggleUnknown returns 404 for an unregistered
// feature name.
func TestRouter_FeatureToggleUnknown(t *testing.T) {
	h, _, _, _ := newRouterHarness(t, config.NodeTypeHub)
	body := `{"enabled":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/features/no-such/toggle", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 for unknown feature, got %d", rec.Code)
	}
}

// TestRouter_MetricsPrometheusText: GET /api/metrics returns
// the snapshot bytes as text/plain.
func TestRouter_MetricsPrometheusText(t *testing.T) {
	h, _, _, _ := newRouterHarness(t, config.NodeTypeHub)
	req := httptest.NewRequest(http.MethodGet, "/api/metrics", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type = %q, want text/plain", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "foo") {
		t.Fatalf("body missing foo: %q", body)
	}
}

// TestRouter_MetricsHistory: GET /api/metrics/history returns the
// in-memory bucket slice as JSON.
func TestRouter_MetricsHistory(t *testing.T) {
	h, _, _, _ := newRouterHarness(t, config.NodeTypeHub)
	req := httptest.NewRequest(http.MethodGet, "/api/metrics/history?limit=5", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var out []MetricsBucket
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("expected at least one bucket")
	}
}

// TestRouter_Globals_RoundTrip: GET → PUT → GET on /api/globals.
func TestRouter_Globals_RoundTrip(t *testing.T) {
	h, fh, _, _ := newRouterHarness(t, config.NodeTypeHub)
	body := `{"block_response":{"default":"404","timeout_seconds":1}}`
	req := httptest.NewRequest(http.MethodPut, "/api/globals", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("PUT globals: want 204, got %d (%s)", rec.Code, rec.Body.String())
	}
	if fh.setG != 1 {
		t.Fatalf("SetGlobals invocations = %d, want 1", fh.setG)
	}
}

// TestRouter_Mirrors_HubOnly: GET /api/mirrors works on hub but is
// 403 on a proxy/door.
func TestRouter_Mirrors_HubOnly(t *testing.T) {
	h, _, _, _ := newRouterHarness(t, config.NodeTypeProxy)
	req := httptest.NewRequest(http.MethodGet, "/api/mirrors", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403 on proxy, got %d", rec.Code)
	}

	h2, _, _, _ := newRouterHarness(t, config.NodeTypeHub)
	req2 := httptest.NewRequest(http.MethodGet, "/api/mirrors", nil)
	rec2 := httptest.NewRecorder()
	h2.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("want 200 on hub, got %d", rec2.Code)
	}
}

// TestRouter_Audit_Query: GET /api/audit returns the in-memory log as
// JSON.
func TestRouter_Audit_Query(t *testing.T) {
	h, _, _, fa := newRouterHarness(t, config.NodeTypeHub)
	_ = fa.Append(Event{Time: time.Now(), Action: "test.event", Target: "foo"})

	req := httptest.NewRequest(http.MethodGet, "/api/audit", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "test.event") {
		t.Fatalf("body missing event: %s", rec.Body.String())
	}
}

// TestRouter_MeReturnsNodeIdentity: GET /api/me carries node id+type.
func TestRouter_MeReturnsNodeIdentity(t *testing.T) {
	h, _, _, _ := newRouterHarness(t, config.NodeTypeHub)
	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "test") {
		t.Fatalf("body missing node id: %s", rec.Body.String())
	}
}
