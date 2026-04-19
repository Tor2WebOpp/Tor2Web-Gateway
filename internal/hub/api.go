package hub

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"sort"
	"strings"
	"time"

	"gateway/internal/config"
)

// nodeIDCtxKey and nodeTypeCtxKey are the request-context keys used for the
// authenticated peer's identity. Exported through With*/FromContext helpers.
type nodeIDCtxKey struct{}
type nodeTypeCtxKey struct{}

// WithNodeID attaches id to ctx. Used by the mTLS middleware after peer
// verification and by tests.
func WithNodeID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, nodeIDCtxKey{}, id)
}

// NodeIDFromContext returns the node ID previously attached via WithNodeID.
// The second return is true when an ID was present and non-empty.
func NodeIDFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	v, ok := ctx.Value(nodeIDCtxKey{}).(string)
	if !ok || v == "" {
		return "", false
	}
	return v, true
}

// WithNodeType attaches t to ctx. Used by the mTLS middleware.
func WithNodeType(ctx context.Context, t string) context.Context {
	return context.WithValue(ctx, nodeTypeCtxKey{}, t)
}

// NodeTypeFromContext returns the authenticated node type and true when
// present.
func NodeTypeFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	v, ok := ctx.Value(nodeTypeCtxKey{}).(string)
	if !ok || v == "" {
		return "", false
	}
	return v, true
}

// API is the hub's admin HTTP surface. It owns no state itself; all
// fields are pointers to collaborators, and the Handler() return is safe
// to install behind a TLS listener once the caller has wired its own
// server-side tls.Config.
//
// The mirror registry and monitor are optional: when mirrors is nil the
// /v1/mirrors routes respond 503; when monitor is nil the immediate-check
// endpoint does the same. The Handler() wiring is identical either way —
// callers can set the fields after construction via With* helpers and
// re-call Handler() safely.
type API struct {
	reg          *Registry
	mirrors      *MirrorRegistry
	monitor      *Monitor
	ca           *CA
	nodes        *NodeStore
	torpoolProxy http.RoundTripper

	logger *slog.Logger
	stream *StreamHandler
}

// NewAPI constructs an API. torpoolSocketPath is the Unix domain socket
// on which the embedded gateway-torpool listens; an empty path disables
// the proxy routes (they return 503).
//
// Mirror registry and monitor are attached via WithMirrors / WithMonitor.
// The zero-mirrors configuration is valid: the /v1/mirrors routes answer
// with 503 until a mirror registry is wired, which lets the hub boot on
// P1 hosts that have not yet rolled out the P2 mirror-health feature.
func NewAPI(reg *Registry, ca *CA, nodes *NodeStore, torpoolSocketPath string) *API {
	a := &API{
		reg:    reg,
		ca:     ca,
		nodes:  nodes,
		logger: slog.Default(),
	}
	a.stream = NewStreamHandler(reg, nodes)
	a.torpoolProxy = newTorpoolRoundTripper(torpoolSocketPath)
	return a
}

// WithMirrors attaches a MirrorRegistry to the API and wires the SSE
// stream handler to forward mirror events. Returns the receiver so calls
// can be chained: NewAPI(...).WithMirrors(mr).WithMonitor(mon). Passing
// nil is a no-op.
func (a *API) WithMirrors(mirrors *MirrorRegistry) *API {
	if mirrors == nil {
		return a
	}
	a.mirrors = mirrors
	if a.stream != nil {
		a.stream.SetMirrors(mirrors)
	}
	return a
}

// WithMonitor attaches a *Monitor so the /v1/mirrors/check endpoint can
// trigger an immediate sweep. Passing nil is a no-op.
func (a *API) WithMonitor(m *Monitor) *API {
	if m == nil {
		return a
	}
	a.monitor = m
	return a
}

// Handler returns the fully-routed http.Handler. All routes except
// /v1/nodes/register sit behind requireMTLS which verifies the peer
// cert against the hub CA and, on success, injects the node identity
// into the request context.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()

	// Tenant registry.
	mux.HandleFunc("GET /v1/tenants", a.requireMTLS(a.handleListTenants))
	mux.HandleFunc("GET /v1/tenants/{host}", a.requireMTLS(a.handleGetTenant))
	mux.HandleFunc("PUT /v1/tenants/{host}", a.requireMTLS(a.handlePutTenant))
	mux.HandleFunc("DELETE /v1/tenants/{host}", a.requireMTLS(a.handleDeleteTenant))

	// Globals.
	mux.HandleFunc("GET /v1/globals", a.requireMTLS(a.handleGetGlobals))
	mux.HandleFunc("PUT /v1/globals", a.requireMTLS(a.handlePutGlobals))

	// Node lifecycle. register is the only unauthenticated endpoint:
	// the installer has no cert when it first contacts the hub.
	mux.HandleFunc("POST /v1/nodes/register", a.handleRegisterNode)
	mux.HandleFunc("GET /v1/nodes", a.requireMTLS(a.handleListNodes))
	mux.HandleFunc("DELETE /v1/nodes/{id}", a.requireMTLS(a.handleDeleteNode))

	// SSE config stream.
	mux.HandleFunc("GET /v1/config/stream", a.requireMTLS(a.stream.ServeHTTP))

	// Mirror-health registry (P2). All routes 503 until a MirrorRegistry
	// is wired via WithMirrors so the hub still boots on P1-only installs.
	mux.HandleFunc("GET /v1/mirrors", a.requireMTLS(a.handleListMirrors))
	mux.HandleFunc("GET /v1/mirrors/{host}", a.requireMTLS(a.handleGetMirror))
	mux.HandleFunc("PUT /v1/mirrors/{host}", a.requireMTLS(a.handlePutMirror))
	mux.HandleFunc("DELETE /v1/mirrors/{host}", a.requireMTLS(a.handleDeleteMirror))
	mux.HandleFunc("POST /v1/mirrors/{host}/force-block", a.requireMTLS(a.handleForceBlockMirror))
	mux.HandleFunc("POST /v1/mirrors/{host}/unblock", a.requireMTLS(a.handleUnblockMirror))
	mux.HandleFunc("POST /v1/mirrors/check", a.requireMTLS(a.handleCheckMirrors))

	// check-host settings (P2). Stored under runtime/settings/checkhost.yaml.
	mux.HandleFunc("GET /v1/settings/checkhost", a.requireMTLS(a.handleGetCheckHostSettings))
	mux.HandleFunc("PUT /v1/settings/checkhost", a.requireMTLS(a.handlePutCheckHostSettings))

	// Torpool passthrough.
	mux.HandleFunc("GET /v1/backends", a.requireMTLS(a.proxyTorpool("/backends", http.MethodGet)))
	mux.HandleFunc("GET /v1/health", a.requireMTLS(a.proxyTorpool("/health", http.MethodGet)))
	mux.HandleFunc("POST /v1/scale", a.requireMTLS(a.proxyTorpool("/scale", http.MethodPost)))

	// Cap every request body before it reaches a handler. json.Decoder has
	// no built-in upper bound, so a misbehaving (even authenticated) client
	// could stream an arbitrarily large object and force the hub to allocate
	// unbounded memory during Decode. 1 MiB comfortably exceeds the largest
	// tenant/globals/mirror payload we emit while blocking abusive bodies.
	return limitRequestBodies(mux, 1<<20)
}

// limitRequestBodies wraps every inbound request with http.MaxBytesReader so
// no downstream Decode/Read can allocate past maxBytes.
func limitRequestBodies(h http.Handler, maxBytes int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		}
		h.ServeHTTP(w, r)
	})
}

// requireMTLS wraps a handler, enforcing valid mTLS peer cert and
// stashing node identity into the request context.
//
// The inner handler runs only when the peer cert validates and was
// issued by this CA. CA-issued but revoked certs fail with 403 so
// operators can distinguish "I don't know you" (401) from "you've been
// kicked out" (403).
func (a *API) requireMTLS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			writeJSONError(w, http.StatusUnauthorized, "mTLS required")
			return
		}
		if a.ca == nil {
			writeJSONError(w, http.StatusInternalServerError, "CA not configured")
			return
		}
		nodeID, nodeType, err := a.ca.VerifyPeer(r.TLS)
		if err != nil {
			// Revoked serials are reported as a signal to the operator
			// but no details are leaked to the peer.
			if strings.Contains(err.Error(), "revoked") {
				writeJSONError(w, http.StatusForbidden, "certificate revoked")
				return
			}
			writeJSONError(w, http.StatusUnauthorized, "cert verification failed")
			return
		}
		a.nodes.Touch(nodeID)
		ctx := WithNodeID(r.Context(), nodeID)
		ctx = WithNodeType(ctx, nodeType)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// handleListTenants serves GET /v1/tenants.
func (a *API) handleListTenants(w http.ResponseWriter, r *http.Request) {
	_, tenants := a.reg.Snapshot()
	// Sorted by host for stable output.
	hosts := make([]string, 0, len(tenants))
	for h := range tenants {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	out := make([]config.TenantConf, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, tenants[h])
	}
	writeJSON(w, http.StatusOK, out)
}

// handleGetTenant serves GET /v1/tenants/{host}.
func (a *API) handleGetTenant(w http.ResponseWriter, r *http.Request) {
	host := r.PathValue("host")
	t, ok := a.reg.Tenant(host)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "tenant not found")
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// handlePutTenant serves PUT /v1/tenants/{host}. Body is a JSON TenantConf.
// If the body's Host is empty the path value is used; if both are set they
// must match to prevent ambiguous writes.
func (a *API) handlePutTenant(w http.ResponseWriter, r *http.Request) {
	host := r.PathValue("host")
	var t config.TenantConf
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	if t.Host == "" {
		t.Host = host
	} else if t.Host != host {
		// Mismatch between path and body is a client-facing contract
		// violation; the two hosts are already in the request, so echoing
		// them back doesn't leak anything the peer can't already see.
		writeJSONError(w, http.StatusBadRequest,
			fmt.Sprintf("body host %q does not match path host %q", t.Host, host))
		return
	}
	if err := a.reg.UpsertTenant(r.Context(), t); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// handleDeleteTenant serves DELETE /v1/tenants/{host}.
func (a *API) handleDeleteTenant(w http.ResponseWriter, r *http.Request) {
	host := r.PathValue("host")
	if err := a.reg.DeleteTenant(r.Context(), host); err != nil {
		apiError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleGetGlobals serves GET /v1/globals.
func (a *API) handleGetGlobals(w http.ResponseWriter, r *http.Request) {
	g, _ := a.reg.Snapshot()
	writeJSON(w, http.StatusOK, g)
}

// handlePutGlobals serves PUT /v1/globals. Body is a JSON GlobalsConf.
func (a *API) handlePutGlobals(w http.ResponseWriter, r *http.Request) {
	var g config.GlobalsConf
	if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	if err := a.reg.SetGlobals(r.Context(), g); err != nil {
		apiError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, g)
}

// handleRegisterNode serves POST /v1/nodes/register. No mTLS; installer
// has not yet obtained a cert at this point.
func (a *API) handleRegisterNode(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	resp, err := a.nodes.Register(req, a.ca)
	if err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

// handleListNodes serves GET /v1/nodes.
func (a *API) handleListNodes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.nodes.AsNodeInfos())
}

// checkHostSettingsRequest is the JSON shape for POST /v1/mirrors/check. The
// request body is optional; an empty body triggers a sweep with the stored
// regions set.
type checkHostCheckRequest struct {
	Regions []string `json:"regions,omitempty"`
}

// forceBlockRequest is the JSON body for POST /v1/mirrors/{host}/force-block.
type forceBlockRequest struct {
	Note string `json:"note"`
}

// handleListMirrors serves GET /v1/mirrors.
func (a *API) handleListMirrors(w http.ResponseWriter, r *http.Request) {
	if a.mirrors == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "mirror registry disabled")
		return
	}
	writeJSON(w, http.StatusOK, a.mirrors.List())
}

// handleGetMirror serves GET /v1/mirrors/{host}.
func (a *API) handleGetMirror(w http.ResponseWriter, r *http.Request) {
	if a.mirrors == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "mirror registry disabled")
		return
	}
	host := r.PathValue("host")
	m, ok := a.mirrors.Get(host)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "mirror not found")
		return
	}
	writeJSON(w, http.StatusOK, m)
}

// handlePutMirror serves PUT /v1/mirrors/{host}. Body is a JSON MirrorHealth.
// Host in the body is forced to match the path value; mismatched hosts are
// rejected with 400 so operators cannot silently write a row under the wrong
// key.
func (a *API) handlePutMirror(w http.ResponseWriter, r *http.Request) {
	if a.mirrors == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "mirror registry disabled")
		return
	}
	host := r.PathValue("host")
	var mh MirrorHealth
	if err := json.NewDecoder(r.Body).Decode(&mh); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	if mh.Host == "" {
		mh.Host = host
	} else if mh.Host != host {
		writeJSONError(w, http.StatusBadRequest,
			fmt.Sprintf("body host %q does not match path host %q", mh.Host, host))
		return
	}
	if err := a.mirrors.Upsert(r.Context(), mh); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	// Return the stored record so clients see the server-applied defaults
	// (Weight=1, Verdict=unknown) rather than whatever shape they sent.
	stored, ok := a.mirrors.Get(host)
	if !ok {
		apiError(w, http.StatusInternalServerError, fmt.Errorf("hub api: mirror missing after upsert"))
		return
	}
	writeJSON(w, http.StatusOK, stored)
}

// handleDeleteMirror serves DELETE /v1/mirrors/{host}.
func (a *API) handleDeleteMirror(w http.ResponseWriter, r *http.Request) {
	if a.mirrors == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "mirror registry disabled")
		return
	}
	host := r.PathValue("host")
	if err := a.mirrors.Delete(r.Context(), host); err != nil {
		apiError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleForceBlockMirror serves POST /v1/mirrors/{host}/force-block. The note
// body is optional; an empty JSON body is accepted.
func (a *API) handleForceBlockMirror(w http.ResponseWriter, r *http.Request) {
	if a.mirrors == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "mirror registry disabled")
		return
	}
	host := r.PathValue("host")
	var req forceBlockRequest
	// Body is optional — a raw POST with no body is valid ("empty note").
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			apiError(w, http.StatusBadRequest, err)
			return
		}
	}
	if err := a.mirrors.ForceBlock(r.Context(), host, req.Note); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	stored, _ := a.mirrors.Get(host)
	writeJSON(w, http.StatusOK, stored)
}

// handleUnblockMirror serves POST /v1/mirrors/{host}/unblock.
func (a *API) handleUnblockMirror(w http.ResponseWriter, r *http.Request) {
	if a.mirrors == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "mirror registry disabled")
		return
	}
	host := r.PathValue("host")
	if err := a.mirrors.Unblock(r.Context(), host); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	stored, ok := a.mirrors.Get(host)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "mirror not found")
		return
	}
	writeJSON(w, http.StatusOK, stored)
}

// handleCheckMirrors serves POST /v1/mirrors/check. Kicks off an immediate
// monitor sweep. The body is optional; when regions are provided they are
// ignored by the Monitor (which always reads settings from disk) but preserved
// for future tuning. Returns 202 on success.
func (a *API) handleCheckMirrors(w http.ResponseWriter, r *http.Request) {
	if a.mirrors == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "mirror registry disabled")
		return
	}
	if a.monitor == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "monitor disabled")
		return
	}
	// Drain the body if supplied; validation failure is non-fatal because
	// the Monitor reads its region list from disk.
	if r.ContentLength > 0 {
		var req checkHostCheckRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	if err := a.monitor.CheckOnce(r.Context()); err != nil {
		apiError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "ok"})
}

// handleGetCheckHostSettings serves GET /v1/settings/checkhost. Missing file
// returns the zero-value struct per LoadCheckHostSettings's contract; the
// caller receives the defaults baked into the Monitor (interval=5m, etc.)
// only implicitly via the monitor's resolveSettings — here we return the
// persisted value as-is so operators can distinguish "not yet configured"
// from an explicit override.
func (a *API) handleGetCheckHostSettings(w http.ResponseWriter, r *http.Request) {
	if a.mirrors == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "mirror registry disabled")
		return
	}
	s, err := LoadCheckHostSettings(a.mirrors.DataDir())
	if err != nil {
		apiError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, s)
}

// handlePutCheckHostSettings serves PUT /v1/settings/checkhost. Body is the
// full CheckHostSettings JSON; partial updates are not supported.
func (a *API) handlePutCheckHostSettings(w http.ResponseWriter, r *http.Request) {
	if a.mirrors == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "mirror registry disabled")
		return
	}
	var s CheckHostSettings
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	if err := SaveCheckHostSettings(a.mirrors.DataDir(), s); err != nil {
		apiError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, s)
}

// handleDeleteNode serves DELETE /v1/nodes/{id}. Revokes the cert and
// removes the record in one step.
func (a *API) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := a.nodes.Delete(id, a.ca); err != nil {
		apiError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// proxyTorpool returns a handler that forwards a request to the embedded
// torpool Unix socket. We rewrite the URL to target the torpool path and
// reuse the shared unix-socket RoundTripper built in NewAPI.
func (a *API) proxyTorpool(torpoolPath, method string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.torpoolProxy == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "torpool proxy disabled")
			return
		}

		u := &url.URL{Scheme: "http", Host: "torpool.local", Path: torpoolPath}
		outReq, err := http.NewRequestWithContext(r.Context(), method, u.String(), r.Body)
		if err != nil {
			apiError(w, http.StatusInternalServerError, err)
			return
		}
		for k, vs := range r.Header {
			if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Connection") {
				continue
			}
			for _, v := range vs {
				outReq.Header.Add(k, v)
			}
		}

		resp, err := a.torpoolProxy.RoundTrip(outReq)
		if err != nil {
			apiError(w, http.StatusBadGateway, err)
			return
		}
		defer resp.Body.Close()

		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}
}

// newTorpoolRoundTripper returns an http.RoundTripper that always dials
// the given Unix socket path. An empty socketPath yields nil, in which
// case proxyTorpool short-circuits to 503.
func newTorpoolRoundTripper(socketPath string) http.RoundTripper {
	if socketPath == "" {
		return nil
	}
	return &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "unix", socketPath)
		},
		MaxIdleConns:    4,
		IdleConnTimeout: 30 * time.Second,
	}
}

// writeJSON is the one-line helper used by every JSON endpoint.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Warn("hub/api: encode response", "error", err)
	}
}

// writeJSONError serializes {"error": msg} with the given status. It is for
// cases where the public message is a static string intentionally exposed to
// authenticated peers (e.g. "invalid tenant host"). Do NOT pass err.Error() —
// use apiError for anything derived from a Go error value.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// apiError logs the underlying error internally and writes a fixed, generic
// public body per status code. Raw Go error strings (file paths, YAML parse
// errors, cert-issuer internals) never reach the wire — even authenticated
// peers see only "bad request", "internal error", etc.
//
// Spec §OPSEC principles #3 forbids leaking filesystem layout or internal
// error detail to the hub's peer surface; this helper is the single seam
// responsible for upholding that invariant.
func apiError(w http.ResponseWriter, status int, err error) {
	slog.Error("hub api error", "status", status, "err", err)
	var msg string
	switch status {
	case http.StatusBadRequest:
		msg = "bad request"
	case http.StatusUnauthorized:
		msg = "unauthorized"
	case http.StatusForbidden:
		msg = "forbidden"
	case http.StatusNotFound:
		msg = "not found"
	case http.StatusConflict:
		msg = "conflict"
	case http.StatusBadGateway:
		msg = "bad gateway"
	case http.StatusServiceUnavailable:
		msg = "service unavailable"
	case http.StatusInternalServerError:
		msg = "internal error"
	default:
		msg = "error"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// SupportsUnixSockets reports whether this runtime can dial Unix sockets.
// On Windows 1803+ AF_UNIX is supported.
func SupportsUnixSockets() bool {
	switch runtime.GOOS {
	case "windows":
		return true
	default:
		return true
	}
}
