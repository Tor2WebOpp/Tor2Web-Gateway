package hub

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"gateway/internal/shared"
)

// streamBuffer is the number of events held per subscriber before the
// oldest is dropped. Deliberately small: hub deltas are rare compared to
// request throughput, and keeping the buffer small guarantees bounded
// memory per client.
const streamBuffer = 64

// StreamHandler serves the SSE config-stream endpoint.
//
// Each request subscribes to the Registry for the duration of the
// connection. The initial snapshot event is written before subscription,
// so a new subscriber never misses the "current state" bootstrap. Deltas
// for tenants not assigned to the caller's node are skipped; globals
// updates are always sent.
//
// When a MirrorRegistry is attached (via SetMirrors) each subscriber also
// receives a mirror_snapshot bootstrap plus all subsequent mirror_upsert/
// mirror_delete deltas. Mirror events are delivered to every authenticated
// mTLS peer regardless of tenant assignment: doors pick redirect targets
// from the live mirror set and proxies log the state for diagnostics.
//
// Node identity is supplied by the mTLS middleware via the request
// context (NodeIDFromContext). Unauthenticated requests still produce a
// valid stream: in that case every tenant is visible. Production callers
// wire the mux behind mTLS before reaching this handler.
type StreamHandler struct {
	reg     *Registry
	mirrors *MirrorRegistry
	nodes   *NodeStore

	// heartbeat controls the keepalive interval. Zero disables heartbeats
	// (tests set this to keep assertions deterministic).
	heartbeat time.Duration
}

// NewStreamHandler returns a StreamHandler wired to the given registry
// and node store. The mirror registry may be attached later via SetMirrors.
func NewStreamHandler(reg *Registry, nodes *NodeStore) *StreamHandler {
	return &StreamHandler{
		reg:       reg,
		nodes:     nodes,
		heartbeat: 30 * time.Second,
	}
}

// SetMirrors attaches a MirrorRegistry so mirror_snapshot / mirror_upsert /
// mirror_delete events are multiplexed into every SSE subscription. Passing
// nil detaches the registry. Thread-safe only in the sense that the API
// calls SetMirrors once at boot, before serving requests.
func (s *StreamHandler) SetMirrors(mirrors *MirrorRegistry) {
	s.mirrors = mirrors
}

// ServeHTTP implements http.Handler.
func (s *StreamHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	nodeID, _ := NodeIDFromContext(r.Context())

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	sub := newStreamSubscriber(streamBuffer)
	unsubscribe := s.reg.Subscribe(sub)
	defer unsubscribe()
	// Registry.Subscribe atomically enqueues a snapshot under the same lock
	// as the broadcast path, so the subscriber's first event is guaranteed
	// to be the initial snapshot and no delta can arrive before it. That
	// means the loop below simply drains; no explicit first-frame write is
	// needed.

	// Mirror subscription is optional. The MirrorRegistry emits MirrorEvent
	// values; we translate them to shared.ConfigStreamEvent so the SSE wire
	// format stays uniform across tenant and mirror deltas.
	if s.mirrors != nil {
		mirrorSub := &mirrorStreamAdapter{out: sub}
		mirrorUnsub := s.mirrors.Subscribe(mirrorSub)
		defer mirrorUnsub()
	}

	// Heartbeat ticker is nil when heartbeats are disabled (tests).
	var tick *time.Ticker
	var tickC <-chan time.Time
	if s.heartbeat > 0 {
		tick = time.NewTicker(s.heartbeat)
		defer tick.Stop()
		tickC = tick.C
	}

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-sub.out:
			if !ok {
				return
			}
			if !s.allow(ev, nodeID) {
				continue
			}
			if ev.Type == shared.EventSnapshot {
				ev = s.filterSnapshot(ev, nodeID)
			}
			if err := writeSSE(w, ev); err != nil {
				return
			}
			flusher.Flush()
		case <-tickC:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// allow filters events by node assignment. Globals events are always
// delivered; tenant upsert/delete are gated by NodeStore assignment. The
// snapshot case is handled separately via filterSnapshot below because
// the event payload is a list of tenants and unmatched entries have to
// be removed rather than the whole event dropped.
//
// Mirror events (mirror_snapshot, mirror_upsert, mirror_delete) fall
// through to the default branch and are always delivered: door nodes need
// the full live-mirror set to pick a redirect target, and proxy nodes
// log the state for diagnostics. No per-tenant filter applies.
func (s *StreamHandler) allow(ev shared.ConfigStreamEvent, nodeID string) bool {
	if nodeID == "" || s.nodes == nil {
		return true
	}
	switch ev.Type {
	case shared.EventGlobalsUpdate:
		return true
	case shared.EventSnapshot:
		return true
	case shared.EventTenantUpsert:
		var ti shared.TenantInfo
		if err := json.Unmarshal(ev.Data, &ti); err != nil {
			return false
		}
		return s.nodes.TenantAllowed(nodeID, ti.Host)
	case shared.EventTenantDelete:
		var payload shared.TenantDeletePayload
		if err := json.Unmarshal(ev.Data, &payload); err != nil {
			return false
		}
		return s.nodes.TenantAllowed(nodeID, payload.Host)
	case shared.EventMirrorSnapshot, shared.EventMirrorUpsert, shared.EventMirrorDelete:
		// Mirror health is broadcast to every authenticated peer.
		return true
	}
	return true
}

// filterSnapshot rewrites a snapshot event so that only tenants assigned
// to the caller remain. Returns the possibly-rewritten event (original if
// the caller is unauthenticated or has full visibility).
func (s *StreamHandler) filterSnapshot(ev shared.ConfigStreamEvent, nodeID string) shared.ConfigStreamEvent {
	if nodeID == "" || s.nodes == nil {
		return ev
	}
	var snap shared.SnapshotPayload
	if err := json.Unmarshal(ev.Data, &snap); err != nil {
		return ev
	}
	filtered := make([]shared.TenantInfo, 0, len(snap.Tenants))
	for _, ti := range snap.Tenants {
		if s.nodes.TenantAllowed(nodeID, ti.Host) {
			filtered = append(filtered, ti)
		}
	}
	snap.Tenants = filtered
	raw, err := json.Marshal(snap)
	if err != nil {
		return ev
	}
	ev.Data = raw
	return ev
}

// writeSSE serializes ev as a single SSE "message" using the "event:" and
// "data:" prefixes. The payload is compact JSON on a single line so the
// data: prefix never leaks into the body.
func writeSSE(w http.ResponseWriter, ev shared.ConfigStreamEvent) error {
	payload, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, payload); err != nil {
		return err
	}
	return nil
}

// streamSubscriber adapts Registry.Subscribe's Subscriber contract to a
// Go channel bounded at streamBuffer. Overflow drops the oldest buffered
// event for this subscriber only.
type streamSubscriber struct {
	mu     sync.Mutex
	out    chan shared.ConfigStreamEvent
	closed bool
}

func newStreamSubscriber(buf int) *streamSubscriber {
	return &streamSubscriber{out: make(chan shared.ConfigStreamEvent, buf)}
}

// OnEvent implements Subscriber. If the channel is full we drop the oldest
// event to make room so the hub's broadcaster is never blocked by a slow
// SSE peer.
func (s *streamSubscriber) OnEvent(ev shared.ConfigStreamEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	select {
	case s.out <- ev:
		return
	default:
	}
	// Drop the oldest and try once more. Under the mutex nothing else can
	// receive from the channel, so this sequence is race-free.
	select {
	case <-s.out:
	default:
	}
	select {
	case s.out <- ev:
	default:
	}
}

// close marks the subscriber as closed and empties the channel so any
// goroutine reading from it unblocks cleanly.
func (s *streamSubscriber) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	close(s.out)
	s.mu.Unlock()
}

// mirrorStreamAdapter bridges MirrorRegistry's MirrorSubscriber interface
// into the SSE stream. Each inbound MirrorEvent is re-encoded as a
// shared.ConfigStreamEvent so StreamHandler can emit a single unified event
// stream for tenant and mirror deltas. Marshal errors on trusted internal
// types are silently dropped — they would only recur on every retry.
type mirrorStreamAdapter struct {
	out *streamSubscriber
}

// OnMirrorEvent implements MirrorSubscriber.
func (a *mirrorStreamAdapter) OnMirrorEvent(ev MirrorEvent) {
	if a == nil || a.out == nil {
		return
	}
	switch ev.Type {
	case MirrorEventSnapshot:
		infos := make([]shared.MirrorInfo, 0, len(ev.Mirrors))
		for _, m := range ev.Mirrors {
			infos = append(infos, mirrorInfoFromHealth(m, ev.Version))
		}
		out, err := shared.NewMirrorSnapshotEvent(infos, ev.Version)
		if err != nil {
			return
		}
		a.out.OnEvent(out)
	case MirrorEventUpsert:
		out, err := shared.NewMirrorUpsertEvent(mirrorInfoFromHealth(ev.Mirror, ev.Version))
		if err != nil {
			return
		}
		a.out.OnEvent(out)
	case MirrorEventDelete:
		out, err := shared.NewMirrorDeleteEvent(ev.Host)
		if err != nil {
			return
		}
		a.out.OnEvent(out)
	}
}

// mirrorInfoFromHealth projects a MirrorHealth into the wire-facing
// shared.MirrorInfo shape. BlockedRegions is derived from the per-region
// status map so downstream consumers (the door's Selector in particular)
// do not have to re-run the failure classification logic client-side.
func mirrorInfoFromHealth(m MirrorHealth, version uint64) shared.MirrorInfo {
	var blocked []string
	for region, rs := range m.Regions {
		if statusIsFailure(rs.Status) {
			blocked = append(blocked, region)
		}
	}
	info := shared.MirrorInfo{
		Host:           m.Host,
		Verdict:        string(m.Verdict),
		ManualBlock:    m.ManualBlock,
		Weight:         m.Weight,
		BlockedRegions: blocked,
		Version:        version,
	}
	if m.TargetTenants != nil {
		info.TargetTenants = append([]string(nil), m.TargetTenants...)
	}
	return info
}
