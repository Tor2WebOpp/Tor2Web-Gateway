package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gateway/internal/config"
	"gateway/internal/hub"
	"gateway/internal/metrics"
)

// HubAccess is the slice of the hub registry that admin routes need.
// Edge nodes (proxy, door) leave this nil; the router refuses
// hub-scoped routes with a fixed 403 in that case.
//
// Implementations are expected to be thread-safe — the production wire
// is *hub.Registry plus *hub.MirrorRegistry, both already concurrent.
type HubAccess interface {
	ListTenants() []config.TenantConf
	GetTenant(host string) (config.TenantConf, bool)
	UpsertTenant(ctx context.Context, t config.TenantConf) error
	DeleteTenant(ctx context.Context, host string) error
	GetGlobals() config.GlobalsConf
	SetGlobals(ctx context.Context, g config.GlobalsConf) error
	ListMirrors() []hub.MirrorHealth
}

// FeatureAccess covers the local-node feature toggles. ListFeatures
// returns the registered feature names plus current global enabled
// state; ToggleGlobal sets the per-node override that the feature's
// resolver picks up at request time.
type FeatureAccess interface {
	ListFeatures() []FeatureStatus
	ToggleGlobal(name string, enabled bool) error
}

// FeatureStatus is the projection returned by FeatureAccess.ListFeatures.
type FeatureStatus struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

// MetricsAccess returns the local Prometheus snapshot and a recent-
// history slice. Snapshot returns Prometheus text-format bytes ready
// for the wire; History returns up to limit buckets of in-memory
// samples (hub UI uses these for sparkline charts).
type MetricsAccess interface {
	Snapshot() []byte
	History(limit int) []MetricsBucket
}

// MetricsBucket is a single time-bucketed metrics snapshot kept in
// memory for the UI's recent-history view. Fields are intentionally
// minimal; the production wire-up populates them from the same
// underlying collectors as the Prometheus exporter.
type MetricsBucket struct {
	At       time.Time `json:"at"`
	RPS      float64   `json:"rps"`
	ErrRate  float64   `json:"err_rate"`
	Backends int       `json:"backends"`
}

// AuditAccess is the contract expected by the router. *Log from
// audit.go satisfies it directly via Write; the indirection lets tests
// substitute an in-memory log.
type AuditAccess interface {
	Query(since time.Time, limit int) ([]Event, error)
	Append(e Event) error
}

// auditAdapter wraps a *Log so it satisfies AuditAccess; *Log uses
// Write rather than Append for historical reasons.
type auditAdapter struct{ l *Log }

// AuditFromLog returns an AuditAccess backed by a *Log.
func AuditFromLog(l *Log) AuditAccess { return &auditAdapter{l: l} }

func (a *auditAdapter) Query(since time.Time, limit int) ([]Event, error) {
	if a == nil || a.l == nil {
		return nil, nil
	}
	return a.l.Query(since, limit)
}

func (a *auditAdapter) Append(e Event) error {
	if a == nil || a.l == nil {
		return nil
	}
	return a.l.Write(e)
}

// Routes carries every dependency the admin API mux needs. NodeType
// gates which routes are wired live: hub-only routes return 403 on
// proxy/door deployments. Hub may be nil on non-hub nodes.
type Routes struct {
	NodeID   string
	NodeType string
	Hub      HubAccess
	Features FeatureAccess
	Metrics  MetricsAccess
	Audit    AuditAccess
	Labeler  *metrics.Labeler
}

// NewRouter returns a populated *http.ServeMux implementing the spec's
// /api routes. The mux is always created; routes that require hub
// access on non-hub nodes write a fixed JSON error with status 403.
//
// The returned mux is the inner router only — it does NOT enforce
// CSRF, sessions, or no-store headers. The outer Handler in handler.go
// does that uniformly across every admin response.
func NewRouter(r Routes) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/me", r.handleMe)
	mux.HandleFunc("/api/logout", r.handleLogout)

	mux.HandleFunc("/api/tenants", r.handleTenants)
	mux.HandleFunc("/api/tenants/", r.handleTenantByHost)

	mux.HandleFunc("/api/globals", r.handleGlobals)

	mux.HandleFunc("/api/mirrors", r.handleMirrors)

	mux.HandleFunc("/api/features", r.handleFeatures)
	mux.HandleFunc("/api/features/", r.handleFeatureToggle)

	mux.HandleFunc("/api/metrics", r.handleMetrics)
	mux.HandleFunc("/api/metrics/history", r.handleMetricsHistory)

	mux.HandleFunc("/api/audit", r.handleAudit)

	return mux
}

// errorJSON writes a small JSON error payload. No stack traces, no
// internal detail — public messages only.
func errorJSON(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{Error: msg})
}

// jsonOK writes v as JSON with status 200.
func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(v)
}

// requireHub is a guard for routes that only make sense on a hub node.
// On non-hub nodes (or if Hub is nil for any reason) it writes the
// stock 403 and returns false; the handler should return immediately.
func (r Routes) requireHub(w http.ResponseWriter) bool {
	if r.NodeType != config.NodeTypeHub || r.Hub == nil {
		errorJSON(w, http.StatusForbidden, "route requires hub node")
		return false
	}
	return true
}

// audit writes an event to the audit log if one is configured. The
// router never fails a request because the audit append failed — that
// would surface a denial-of-service vector via the audit subsystem —
// but it does swallow errors silently so the calling handler stays
// simple.
func (r Routes) audit(req *http.Request, action, target string, diff map[string]any) {
	if r.Audit == nil {
		return
	}
	ev := Event{
		Time:    time.Now().UTC(),
		Action:  action,
		Target:  target,
		Diff:    diff,
		NodeID:  r.NodeID,
		ActorIP: clientIPHash(req, r.Labeler),
	}
	if sid := SessionIDFromRequest(req); sid != "" {
		ev.SessionID = sid
		ev.Actor = sid
	}
	_ = r.Audit.Append(ev)
}

// clientIPHash extracts the remote IP from r and runs it through the
// labeler. Returns "" when the labeler is nil so callers can short-
// circuit.
func clientIPHash(r *http.Request, l *metrics.Labeler) string {
	if l == nil || r == nil {
		return ""
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return l.ClientIP(host)
}

// handleMe returns the current session identity and node info. The
// session lookup happens in the outer Handler; this route only needs
// the cookie value plus the configured node identity.
func (r Routes) handleMe(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		errorJSON(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	jsonOK(w, struct {
		NodeID    string `json:"node_id"`
		NodeType  string `json:"node_type"`
		SessionID string `json:"session_id,omitempty"`
	}{
		NodeID:    r.NodeID,
		NodeType:  r.NodeType,
		SessionID: SessionIDFromRequest(req),
	})
}

// handleLogout is mounted under /api/logout for clients that prefer
// the JSON form; the bare /logout path on the gate-stripped tree is
// served by the outer Handler so the cookie clear works without
// touching the API mux.
func (r Routes) handleLogout(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		errorJSON(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	r.audit(req, "session.logout", "", nil)
	w.WriteHeader(http.StatusNoContent)
}

// handleTenants serves GET /api/tenants — the full list — and
// rejects everything else with 405. PUT/DELETE on a single host live
// under /api/tenants/{host}.
func (r Routes) handleTenants(w http.ResponseWriter, req *http.Request) {
	if !r.requireHub(w) {
		return
	}
	if req.Method != http.MethodGet {
		errorJSON(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	jsonOK(w, r.Hub.ListTenants())
}

// handleTenantByHost serves GET/PUT/DELETE for /api/tenants/{host}.
// The host is the last URL segment.
func (r Routes) handleTenantByHost(w http.ResponseWriter, req *http.Request) {
	if !r.requireHub(w) {
		return
	}
	host := strings.TrimPrefix(req.URL.Path, "/api/tenants/")
	if host == "" || strings.Contains(host, "/") {
		errorJSON(w, http.StatusBadRequest, "host segment required")
		return
	}
	switch req.Method {
	case http.MethodGet:
		t, ok := r.Hub.GetTenant(host)
		if !ok {
			errorJSON(w, http.StatusNotFound, "no such tenant")
			return
		}
		jsonOK(w, t)
	case http.MethodPut:
		var t config.TenantConf
		if err := json.NewDecoder(req.Body).Decode(&t); err != nil {
			errorJSON(w, http.StatusBadRequest, "bad JSON body")
			return
		}
		if t.Host == "" {
			t.Host = host
		}
		if t.Host != host {
			errorJSON(w, http.StatusBadRequest, "body host does not match URL host")
			return
		}
		if err := r.Hub.UpsertTenant(req.Context(), t); err != nil {
			errorJSON(w, http.StatusInternalServerError, "upsert failed")
			return
		}
		r.audit(req, "tenant.upsert", host, map[string]any{"after": t})
		w.WriteHeader(http.StatusNoContent)
	case http.MethodDelete:
		if err := r.Hub.DeleteTenant(req.Context(), host); err != nil {
			errorJSON(w, http.StatusInternalServerError, "delete failed")
			return
		}
		r.audit(req, "tenant.delete", host, nil)
		w.WriteHeader(http.StatusNoContent)
	default:
		errorJSON(w, http.StatusMethodNotAllowed, "GET, PUT, DELETE only")
	}
}

// handleGlobals serves GET/PUT for /api/globals.
func (r Routes) handleGlobals(w http.ResponseWriter, req *http.Request) {
	if !r.requireHub(w) {
		return
	}
	switch req.Method {
	case http.MethodGet:
		jsonOK(w, r.Hub.GetGlobals())
	case http.MethodPut:
		var g config.GlobalsConf
		if err := json.NewDecoder(req.Body).Decode(&g); err != nil {
			errorJSON(w, http.StatusBadRequest, "bad JSON body")
			return
		}
		if err := r.Hub.SetGlobals(req.Context(), g); err != nil {
			errorJSON(w, http.StatusInternalServerError, "set globals failed")
			return
		}
		r.audit(req, "globals.set", "", map[string]any{"after": g})
		w.WriteHeader(http.StatusNoContent)
	default:
		errorJSON(w, http.StatusMethodNotAllowed, "GET, PUT only")
	}
}

// handleMirrors serves GET /api/mirrors. Mutating operations (force-
// block, weight, settings) are reserved for the dedicated mirror
// admin routes added in P4 once the UI shape is fixed.
func (r Routes) handleMirrors(w http.ResponseWriter, req *http.Request) {
	if !r.requireHub(w) {
		return
	}
	if req.Method != http.MethodGet {
		errorJSON(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	jsonOK(w, r.Hub.ListMirrors())
}

// handleFeatures serves GET /api/features.
func (r Routes) handleFeatures(w http.ResponseWriter, req *http.Request) {
	if r.Features == nil {
		errorJSON(w, http.StatusServiceUnavailable, "feature registry not wired")
		return
	}
	if req.Method != http.MethodGet {
		errorJSON(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	jsonOK(w, r.Features.ListFeatures())
}

// handleFeatureToggle handles POST /api/features/{name}/toggle. The
// body is a small JSON object {"enabled": bool}; we accept either
// boolean to keep curl-driven workflows simple.
func (r Routes) handleFeatureToggle(w http.ResponseWriter, req *http.Request) {
	if r.Features == nil {
		errorJSON(w, http.StatusServiceUnavailable, "feature registry not wired")
		return
	}
	if req.Method != http.MethodPost {
		errorJSON(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	rest := strings.TrimPrefix(req.URL.Path, "/api/features/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] != "toggle" {
		errorJSON(w, http.StatusNotFound, "expected /api/features/{name}/toggle")
		return
	}
	name := parts[0]
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		errorJSON(w, http.StatusBadRequest, "bad JSON body")
		return
	}
	if err := r.Features.ToggleGlobal(name, body.Enabled); err != nil {
		if errors.Is(err, errFeatureUnknown) {
			errorJSON(w, http.StatusNotFound, "no such feature")
			return
		}
		errorJSON(w, http.StatusInternalServerError, "toggle failed")
		return
	}
	r.audit(req, "feature.toggle", name, map[string]any{"enabled": body.Enabled})
	w.WriteHeader(http.StatusNoContent)
}

// errFeatureUnknown is the sentinel that FeatureAccess implementations
// should return when the named feature does not exist. The router
// translates it to 404 so callers do not have to special-case it.
var errFeatureUnknown = errors.New("admin: unknown feature")

// ErrUnknownFeature exposes the sentinel for FeatureAccess
// implementations to import.
func ErrUnknownFeature() error { return errFeatureUnknown }

// handleMetrics serves the Prometheus text snapshot.
func (r Routes) handleMetrics(w http.ResponseWriter, req *http.Request) {
	if r.Metrics == nil {
		errorJSON(w, http.StatusServiceUnavailable, "metrics not wired")
		return
	}
	if req.Method != http.MethodGet {
		errorJSON(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	body := r.Metrics.Snapshot()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// handleMetricsHistory serves the in-memory time-bucket history. The
// limit query parameter caps the response; default 60.
func (r Routes) handleMetricsHistory(w http.ResponseWriter, req *http.Request) {
	if r.Metrics == nil {
		errorJSON(w, http.StatusServiceUnavailable, "metrics not wired")
		return
	}
	if req.Method != http.MethodGet {
		errorJSON(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	limit := 60
	if v := req.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	jsonOK(w, r.Metrics.History(limit))
}

// handleAudit serves the audit query API. since=RFC3339 limits to
// events strictly after the timestamp; limit caps the result count.
func (r Routes) handleAudit(w http.ResponseWriter, req *http.Request) {
	if r.Audit == nil {
		errorJSON(w, http.StatusServiceUnavailable, "audit log not wired")
		return
	}
	if req.Method != http.MethodGet {
		errorJSON(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	since := time.Time{}
	if v := req.URL.Query().Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			errorJSON(w, http.StatusBadRequest, "since must be RFC3339")
			return
		}
		since = t
	}
	limit := 100
	if v := req.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 5000 {
			limit = n
		}
	}
	events, err := r.Audit.Query(since, limit)
	if err != nil {
		errorJSON(w, http.StatusInternalServerError, "query failed")
		return
	}
	jsonOK(w, events)
}
