// Mock implementations of the admin Routes collaborator interfaces.
// Returns realistic but neutral data so the rendered admin UI shows
// non-empty tables/cards across every page.
//
// All hostnames use *.example as per the screenshot runner spec — never
// a real domain or project codename.

package main

import (
	"context"
	"sync"
	"time"

	"gateway/internal/admin"
	"gateway/internal/config"
	"gateway/internal/hub"
)

// mockHub satisfies admin.HubAccess. Backed by a copy-on-read map so a
// PUT/DELETE invoked from the UI mutates state visible to subsequent
// GETs without ever escaping the runner process.
type mockHub struct {
	mu      sync.RWMutex
	tenants map[string]config.TenantConf
	mirrors []hub.MirrorHealth
	globals config.GlobalsConf
}

func newMockHub() *mockHub {
	now := time.Now().UTC()

	tenants := []config.TenantConf{
		{
			Host:    "example-a.example",
			Enabled: true,
			Backends: []config.BackendConf{
				{Addr: "10.0.1.10:8080", Weight: 1},
				{Addr: "10.0.1.11:8080", Weight: 1},
			},
			Features: map[string]config.FeatureConf{
				"abuse_api": {Enabled: true},
			},
		},
		{
			Host:    "example-b.example",
			Enabled: true,
			Backends: []config.BackendConf{
				{Addr: "10.0.2.20:8080", Weight: 2},
			},
		},
		{
			Host:    "example-c.example",
			Enabled: false,
			Backends: []config.BackendConf{
				{Addr: "10.0.3.30:8080", Weight: 1},
			},
		},
		{
			Host:    "example-d.example",
			Enabled: true,
			Backends: []config.BackendConf{
				{Addr: "10.0.4.40:8080", Weight: 1},
				{Addr: "10.0.4.41:8080", Weight: 1},
				{Addr: "10.0.4.42:8080", Weight: 1},
			},
		},
	}

	mirrors := []hub.MirrorHealth{
		{
			Host:         "mirror-1.example",
			LastCheck:    now.Add(-2 * time.Minute),
			Verdict:      hub.VerdictLive,
			TotalChecked: 240,
			BlockedCount: 0,
			Weight:       10,
			Regions: map[string]hub.RegionStatus{
				"us-east": {Status: "ok", LatencyMs: 42, At: now.Add(-2 * time.Minute)},
				"eu-west": {Status: "ok", LatencyMs: 89, At: now.Add(-2 * time.Minute)},
			},
		},
		{
			Host:         "mirror-2.example",
			LastCheck:    now.Add(-3 * time.Minute),
			Verdict:      hub.VerdictLive,
			TotalChecked: 230,
			BlockedCount: 0,
			Weight:       10,
		},
		{
			Host:         "mirror-3.example",
			LastCheck:    now.Add(-5 * time.Minute),
			Verdict:      hub.VerdictDegraded,
			TotalChecked: 210,
			BlockedCount: 22,
			Weight:       5,
		},
		{
			Host:         "mirror-4.example",
			LastCheck:    now.Add(-1 * time.Minute),
			Verdict:      hub.VerdictLive,
			TotalChecked: 198,
			BlockedCount: 1,
			Weight:       10,
		},
		{
			Host:         "mirror-5.example",
			LastCheck:    now.Add(-7 * time.Minute),
			Verdict:      hub.VerdictBlocked,
			TotalChecked: 312,
			BlockedCount: 165,
			Weight:       0,
			ManualBlock:  true,
			ManualNote:   "blocked by operator",
		},
		{
			Host:         "mirror-6.example",
			LastCheck:    now.Add(-4 * time.Minute),
			Verdict:      hub.VerdictLive,
			TotalChecked: 174,
			BlockedCount: 0,
			Weight:       10,
		},
		{
			Host:         "mirror-7.example",
			LastCheck:    now.Add(-9 * time.Minute),
			Verdict:      hub.VerdictDegraded,
			TotalChecked: 187,
			BlockedCount: 41,
			Weight:       3,
		},
		{
			Host:         "mirror-8.example",
			LastCheck:    now.Add(-15 * time.Minute),
			Verdict:      hub.VerdictUnknown,
			TotalChecked: 12,
			BlockedCount: 0,
			Weight:       1,
		},
	}

	globals := config.GlobalsConf{
		BlockResponse: config.BlockResponseConf{
			Default:        config.Block404,
			TimeoutSeconds: 5,
		},
		Headers: config.HeadersConf{
			StripUpstream: []string{"server", "x-powered-by"},
		},
	}

	tm := make(map[string]config.TenantConf, len(tenants))
	for _, t := range tenants {
		tm[t.Host] = t
	}
	return &mockHub{
		tenants: tm,
		mirrors: mirrors,
		globals: globals,
	}
}

func (m *mockHub) ListTenants() []config.TenantConf {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]config.TenantConf, 0, len(m.tenants))
	for _, t := range m.tenants {
		out = append(out, t)
	}
	return out
}

func (m *mockHub) GetTenant(host string) (config.TenantConf, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tenants[host]
	return t, ok
}

func (m *mockHub) UpsertTenant(_ context.Context, t config.TenantConf) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tenants[t.Host] = t
	return nil
}

func (m *mockHub) DeleteTenant(_ context.Context, host string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tenants, host)
	return nil
}

func (m *mockHub) GetGlobals() config.GlobalsConf {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.globals
}

func (m *mockHub) SetGlobals(_ context.Context, g config.GlobalsConf) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.globals = g
	return nil
}

func (m *mockHub) ListMirrors() []hub.MirrorHealth {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]hub.MirrorHealth, len(m.mirrors))
	copy(out, m.mirrors)
	return out
}

// mockFeatures satisfies admin.FeatureAccess. Nine features, five
// initially enabled.
type mockFeatures struct {
	mu     sync.Mutex
	states map[string]bool
	order  []string
}

func newMockFeatures() *mockFeatures {
	order := []string{
		"abuse_api",
		"negative_cache",
		"mirror_failover",
		"stealth_hs",
		"rate_limit",
		"opsec_hashing",
		"audit_strict",
		"auto_domains",
		"experimental_quic",
	}
	states := map[string]bool{
		"abuse_api":         true,
		"negative_cache":    true,
		"mirror_failover":   true,
		"stealth_hs":        false,
		"rate_limit":        true,
		"opsec_hashing":     true,
		"audit_strict":      false,
		"auto_domains":      false,
		"experimental_quic": false,
	}
	return &mockFeatures{states: states, order: order}
}

func (m *mockFeatures) ListFeatures() []admin.FeatureStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]admin.FeatureStatus, 0, len(m.order))
	for _, name := range m.order {
		out = append(out, admin.FeatureStatus{Name: name, Enabled: m.states[name]})
	}
	return out
}

func (m *mockFeatures) ToggleGlobal(name string, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.states[name]; !ok {
		return admin.ErrUnknownFeature()
	}
	m.states[name] = enabled
	return nil
}

// mockMetrics satisfies admin.MetricsAccess. The Snapshot blob mimics
// the shape of a real Prometheus dump so the dashboard's loose parser
// produces a sensible "lines" count.
type mockMetrics struct{}

func newMockMetrics() *mockMetrics { return &mockMetrics{} }

const promBody = `# HELP gateway_requests_total Total request count.
# TYPE gateway_requests_total counter
gateway_requests_total{tenant="example-a",code="200"} 4821
gateway_requests_total{tenant="example-a",code="404"} 12
gateway_requests_total{tenant="example-b",code="200"} 1942
gateway_requests_total{tenant="example-c",code="200"} 0
gateway_requests_total{tenant="example-d",code="200"} 587
# HELP gateway_request_duration_seconds Request latency histogram.
# TYPE gateway_request_duration_seconds histogram
gateway_request_duration_seconds_bucket{le="0.005"} 320
gateway_request_duration_seconds_bucket{le="0.01"} 880
gateway_request_duration_seconds_bucket{le="0.05"} 4210
gateway_request_duration_seconds_bucket{le="0.1"} 5128
gateway_request_duration_seconds_bucket{le="+Inf"} 5347
gateway_request_duration_seconds_sum 219.4
gateway_request_duration_seconds_count 5347
# HELP gateway_backend_up Whether the backend is healthy.
# TYPE gateway_backend_up gauge
gateway_backend_up{addr="10.0.1.10:8080"} 1
gateway_backend_up{addr="10.0.1.11:8080"} 1
gateway_backend_up{addr="10.0.2.20:8080"} 1
gateway_backend_up{addr="10.0.3.30:8080"} 0
gateway_backend_up{addr="10.0.4.40:8080"} 1
gateway_backend_up{addr="10.0.4.41:8080"} 1
gateway_backend_up{addr="10.0.4.42:8080"} 1
# HELP gateway_mirrors_live Mirrors currently in rotation.
# TYPE gateway_mirrors_live gauge
gateway_mirrors_live 5
# HELP gateway_audit_events_total Audit events written.
# TYPE gateway_audit_events_total counter
gateway_audit_events_total 12
`

func (m *mockMetrics) Snapshot() []byte { return []byte(promBody) }

func (m *mockMetrics) History(limit int) []admin.MetricsBucket {
	if limit <= 0 || limit > 60 {
		limit = 60
	}
	now := time.Now().UTC()
	// Generate a soft sine-like RPS curve so the sparkline is non-trivial.
	out := make([]admin.MetricsBucket, 0, limit)
	for i := 0; i < limit; i++ {
		rps := 12.0 + float64((i*7)%23)
		errRate := 0.5 + float64((i*3)%5)/10.0
		out = append(out, admin.MetricsBucket{
			At:       now.Add(time.Duration(-(limit - i)) * time.Minute),
			RPS:      rps,
			ErrRate:  errRate,
			Backends: 7,
		})
	}
	return out
}

// mockAudit satisfies admin.AuditAccess. Twelve seeded events plus
// any later Append() from in-page actions land here.
type mockAudit struct {
	mu     sync.Mutex
	events []admin.Event
}

func newMockAudit() *mockAudit {
	now := time.Now().UTC()
	seeded := []admin.Event{
		{Time: now.Add(-30 * time.Minute), Action: "tenant.upsert", Target: "example-a.example", Actor: "session-aaa", NodeID: "screenshot-node"},
		{Time: now.Add(-28 * time.Minute), Action: "tenant.upsert", Target: "example-b.example", Actor: "session-aaa", NodeID: "screenshot-node"},
		{Time: now.Add(-25 * time.Minute), Action: "feature.toggle", Target: "abuse_api", Actor: "session-bbb", NodeID: "screenshot-node", Diff: map[string]any{"enabled": true}},
		{Time: now.Add(-22 * time.Minute), Action: "globals.set", Target: "", Actor: "session-aaa", NodeID: "screenshot-node"},
		{Time: now.Add(-19 * time.Minute), Action: "mirror.block", Target: "mirror-5.example", Actor: "session-ccc", NodeID: "screenshot-node"},
		{Time: now.Add(-15 * time.Minute), Action: "tenant.delete", Target: "example-stale.example", Actor: "session-ccc", NodeID: "screenshot-node"},
		{Time: now.Add(-12 * time.Minute), Action: "feature.toggle", Target: "rate_limit", Actor: "session-aaa", NodeID: "screenshot-node", Diff: map[string]any{"enabled": true}},
		{Time: now.Add(-10 * time.Minute), Action: "session.logout", Target: "", Actor: "session-bbb", NodeID: "screenshot-node"},
		{Time: now.Add(-8 * time.Minute), Action: "tenant.upsert", Target: "example-d.example", Actor: "session-aaa", NodeID: "screenshot-node"},
		{Time: now.Add(-6 * time.Minute), Action: "node.revoke", Target: "node-edge-2", Actor: "session-aaa", NodeID: "screenshot-node"},
		{Time: now.Add(-4 * time.Minute), Action: "mirror.unblock", Target: "mirror-3.example", Actor: "session-ccc", NodeID: "screenshot-node"},
		{Time: now.Add(-2 * time.Minute), Action: "feature.toggle", Target: "audit_strict", Actor: "session-aaa", NodeID: "screenshot-node", Diff: map[string]any{"enabled": false}},
	}
	return &mockAudit{events: seeded}
}

func (m *mockAudit) Query(since time.Time, limit int) ([]admin.Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]admin.Event, 0, len(m.events))
	for _, e := range m.events {
		if !since.IsZero() && !e.Time.After(since) {
			continue
		}
		out = append(out, e)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (m *mockAudit) Append(e admin.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, e)
	return nil
}
