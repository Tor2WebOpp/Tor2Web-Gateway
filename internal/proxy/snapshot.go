package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"gateway/internal/config"
	"gateway/internal/feature"
	"gateway/internal/hub"
	"gateway/internal/shared"
	"gateway/internal/transport"
)

// SnapshotClient is the contract implemented by every snapshot source.
// Start spawns the background goroutine that feeds feature.Registry
// reloads; it returns after performing the initial synchronous load so
// callers can tell when the registry is first usable. Close stops the
// goroutine and must be idempotent.
type SnapshotClient interface {
	Start(ctx context.Context) error
	Close() error
}

// NewSnapshotClient returns the SnapshotClient appropriate for cfg. In
// local mode the hub.Registry is read from cfg.Hub.DataDir (or a legacy
// path) and fsnotify drives reloads. In remote mode the transport's
// admin client subscribes to /v1/config/stream and parses SSE events.
//
// A nil registry is rejected; cfg may be nil, in which case a noop client
// is returned (callers that do not drive the registry still get a valid
// value they can Start/Close).
func NewSnapshotClient(cfg *config.Config, t transport.Transport, reg *feature.Registry) SnapshotClient {
	if reg == nil {
		return &noopClient{}
	}
	if cfg == nil {
		return &noopClient{}
	}
	switch cfg.Mode {
	case config.ModeRemote:
		return NewRemoteClient(cfg, t, reg)
	case config.ModeLocal:
		return NewLocalClient(cfg, reg)
	default:
		return &noopClient{}
	}
}

// noopClient is returned when neither mode is configured. Start/Close
// succeed without performing any work.
type noopClient struct{}

func (n *noopClient) Start(ctx context.Context) error { return nil }
func (n *noopClient) Close() error                    { return nil }

// ---------------------------------------------------------------------
// Local mode client.

// LocalClient reads tenant and globals YAML from cfg.Hub.DataDir via
// hub.Registry and pushes translated snapshots into feature.Registry on
// every fsnotify-triggered reload.
//
// When cfg.Hub.DataDir is empty LocalClient still returns a usable value
// but Start performs no work — callers in legacy single-tenant mode get
// the synthesised implicit tenant via HostRouterFromConfig instead.
type LocalClient struct {
	cfg *config.Config
	reg *feature.Registry

	mu         sync.Mutex
	hubReg     *hub.Registry
	subUnsub   func()
	closeOnce  sync.Once
	cancelFn   context.CancelFunc
	cancelDone chan struct{}
}

// NewLocalClient constructs a local-mode snapshot client. The returned
// client must have Start called once before it emits reloads; Close may
// be called at any point and is safe to call concurrently with Start.
func NewLocalClient(cfg *config.Config, reg *feature.Registry) *LocalClient {
	return &LocalClient{cfg: cfg, reg: reg}
}

// Start performs the initial load and begins listening for fsnotify
// events. It returns after the initial registry.Reload completes so
// callers can trust that the feature registry is populated before
// serving requests. If the data dir is empty Start is a no-op.
func (c *LocalClient) Start(ctx context.Context) error {
	if c.cfg.Hub.DataDir == "" {
		return nil
	}
	hreg, err := hub.New(c.cfg.Hub.DataDir)
	if err != nil {
		return fmt.Errorf("snapshot/local: open hub registry: %w", err)
	}

	c.mu.Lock()
	c.hubReg = hreg
	subCh := make(chan shared.ConfigStreamEvent, 8)
	sub := &chanSubscriber{ch: subCh}
	c.subUnsub = hreg.Subscribe(sub)
	runCtx, cancel := context.WithCancel(ctx)
	c.cancelFn = cancel
	c.cancelDone = make(chan struct{})
	c.mu.Unlock()

	// Perform the initial reload synchronously using whatever the hub
	// loaded from disk. Subscribe already enqueues a snapshot event for
	// this subscriber, so the first event on subCh is a snapshot; we
	// apply it once before spinning the goroutine.
	select {
	case ev := <-subCh:
		if err := applyEvent(c.reg, ev, hreg); err != nil {
			slog.Warn("snapshot/local: initial reload", "err", err)
		}
	case <-ctx.Done():
		cancel()
		return ctx.Err()
	}

	go c.run(runCtx, subCh, hreg)
	return nil
}

// run drains subsequent events from the subscriber channel and applies
// them to the feature registry. It exits when either the context is
// cancelled or the channel is closed by hub.Registry.Close.
func (c *LocalClient) run(ctx context.Context, subCh <-chan shared.ConfigStreamEvent, hreg *hub.Registry) {
	defer close(c.cancelDone)
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-subCh:
			if !ok {
				return
			}
			if err := applyEvent(c.reg, ev, hreg); err != nil {
				slog.Warn("snapshot/local: reload failed", "err", err)
			}
		}
	}
}

// Close releases the hub registry and the subscription. Multiple calls
// are safe; only the first has effect.
func (c *LocalClient) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.mu.Lock()
		cancel := c.cancelFn
		done := c.cancelDone
		unsub := c.subUnsub
		hreg := c.hubReg
		c.mu.Unlock()

		if cancel != nil {
			cancel()
		}
		if unsub != nil {
			unsub()
		}
		if done != nil {
			<-done
		}
		if hreg != nil {
			err = hreg.Close()
		}
	})
	return err
}

// chanSubscriber adapts a plain channel to hub.Subscriber. Overflow
// drops the oldest event, matching the hub's own subscriber semantics.
type chanSubscriber struct {
	mu     sync.Mutex
	ch     chan shared.ConfigStreamEvent
	closed bool
}

// OnEvent implements hub.Subscriber.
func (s *chanSubscriber) OnEvent(ev shared.ConfigStreamEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	select {
	case s.ch <- ev:
		return
	default:
	}
	// Drop oldest and retry.
	select {
	case <-s.ch:
	default:
	}
	select {
	case s.ch <- ev:
	default:
	}
}

// ---------------------------------------------------------------------
// Remote mode client.

// RemoteClient subscribes to the hub's SSE config stream via the
// transport's admin HTTP client. It reconnects with exponential backoff
// if the stream disconnects and feeds translated snapshots into the
// feature registry.
type RemoteClient struct {
	cfg       *config.Config
	transport transport.Transport
	reg       *feature.Registry

	// minBackoff and maxBackoff govern reconnection pacing. They are
	// exposed as package-private fields so tests can shorten them
	// without racing real-time timers.
	minBackoff time.Duration
	maxBackoff time.Duration

	// initialTimeout caps the synchronous first-attempt connect in
	// Start. Returning an error after this elapsed saves a bootstrap
	// process from hanging indefinitely on an unreachable hub. Tests
	// shorten this to keep the suite snappy.
	initialTimeout time.Duration

	// State held by Start.
	state state

	// streamURLOverride lets tests point the client at an httptest
	// server. When empty, cfg.HubURL + "/v1/config/stream" is used.
	streamURLOverride string
}

// state bundles the fields Start / Close share so lock discipline is
// confined to a single struct rather than spread across RemoteClient.
type state struct {
	mu         sync.Mutex
	cancelFn   context.CancelFunc
	cancelDone chan struct{}
	closeOnce  sync.Once
}

// NewRemoteClient constructs a remote-mode snapshot client. The
// transport's admin client is used to dial the hub; cfg.HubURL is the
// base URL for the stream endpoint.
func NewRemoteClient(cfg *config.Config, t transport.Transport, reg *feature.Registry) *RemoteClient {
	return &RemoteClient{
		cfg:            cfg,
		transport:      t,
		reg:            reg,
		minBackoff:     500 * time.Millisecond,
		maxBackoff:     30 * time.Second,
		initialTimeout: 10 * time.Second,
	}
}

// SetStreamURL overrides the SSE endpoint. Intended for tests.
func (c *RemoteClient) SetStreamURL(u string) {
	c.streamURLOverride = u
}

// Start performs a synchronous first connection attempt against the
// hub's SSE endpoint. If that first attempt succeeds (status 200 and
// the initial snapshot event consumed), the reconnect/run goroutine is
// spawned and Start returns nil. If the first attempt fails — transport
// error, non-200 status, or no initial event within initialTimeout —
// Start returns that error and no goroutine is spawned. This lets
// callers distinguish "hub unreachable" from "transient stream churn
// after boot".
func (c *RemoteClient) Start(ctx context.Context) error {
	// Bound the first attempt separately so a wedged hub does not hang
	// the bootstrap path indefinitely. The reconnect loop re-uses the
	// caller's ctx, so Close (or the caller cancelling ctx) still
	// terminates the goroutine promptly.
	timeout := c.initialTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	attemptCtx, attemptCancel := context.WithTimeout(ctx, timeout)
	resp, err := c.openStream(attemptCtx)
	if err != nil {
		attemptCancel()
		return fmt.Errorf("snapshot/remote: initial connect: %w", err)
	}
	// Consume exactly one event off the stream so Start observes the
	// initial snapshot the hub sends on every new subscription. Any
	// failure here (body closed early, parse failure, no event before
	// timeout) is also a startup error — we refuse to hand the client
	// off to the reconnect loop with an un-initialised registry.
	//
	// We wrap resp.Body in a buffered reader once and keep it for the
	// reconnect goroutine; otherwise buffered-but-unread bytes from the
	// initial parse would be lost on handoff.
	br := bufio.NewReader(resp.Body)
	if err := c.readInitialEvent(attemptCtx, br); err != nil {
		resp.Body.Close()
		attemptCancel()
		return fmt.Errorf("snapshot/remote: initial snapshot: %w", err)
	}
	attemptCancel()

	// First attempt succeeded: set up shutdown plumbing and hand the
	// already-open response off to the run goroutine so it can keep
	// draining events without opening a second connection.
	c.state.mu.Lock()
	runCtx, cancel := context.WithCancel(ctx)
	c.state.cancelFn = cancel
	c.state.cancelDone = make(chan struct{})
	c.state.mu.Unlock()

	go c.run(runCtx, resp, br)
	return nil
}

// Close stops the reconnect loop. Safe to call multiple times.
func (c *RemoteClient) Close() error {
	c.state.closeOnce.Do(func() {
		c.state.mu.Lock()
		cancel := c.state.cancelFn
		done := c.state.cancelDone
		c.state.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		if done != nil {
			<-done
		}
	})
	return nil
}

// run is the reconnection loop. The first iteration drains the
// already-open response that Start handed off; subsequent iterations
// open fresh connections via connectAndConsume. Backoff grows
// exponentially between failures and is capped at maxBackoff.
func (c *RemoteClient) run(ctx context.Context, initial *http.Response, buffered *bufio.Reader) {
	defer close(c.state.cancelDone)

	backoff := c.minBackoff

	// Drain the pre-opened stream first. Start already read the
	// initial snapshot event off buffered; consumeStreamReader keeps
	// going until the body ends or ctx fires.
	if initial != nil {
		err := c.consumeStreamReader(ctx, buffered)
		initial.Body.Close()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			slog.Warn("snapshot/remote: stream disconnected", "err", err)
		}
		// Wait one backoff before the first reconnect so a hub that
		// immediately slams the connection shut can't be polled in a
		// tight loop.
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > c.maxBackoff {
			backoff = c.maxBackoff
		}
	}

	for {
		if ctx.Err() != nil {
			return
		}
		err := c.connectAndConsume(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			slog.Warn("snapshot/remote: stream disconnected", "err", err)
		}
		// Reconnect after a backoff.
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > c.maxBackoff {
			backoff = c.maxBackoff
		}
	}
}

// openStream performs the HTTP request against the SSE endpoint and
// returns the response on 200. Non-200 statuses and transport errors
// surface as errors; the caller owns resp.Body and must close it.
func (c *RemoteClient) openStream(ctx context.Context) (*http.Response, error) {
	url := c.streamURL()
	if url == "" {
		return nil, errors.New("hub URL is empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")

	client := http.DefaultClient
	if c.transport != nil {
		if ac := c.transport.AdminClient(); ac != nil {
			client = ac
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("hub stream: status %d", resp.StatusCode)
	}
	return resp, nil
}

// readInitialEvent blocks until one SSE event is parsed off br and
// applied to the registry, or until ctx fires. Used by Start so the
// registry is populated before it returns. The caller owns the
// underlying body and must keep it open for the subsequent reconnect
// loop if this function returns nil.
//
// Reading runs in its own goroutine so we can honour ctx even if the
// underlying connection doesn't cooperate with context cancellation.
// On ctx.Done the stranded goroutine is harmless: the caller will
// close the body immediately after, which unblocks any pending read.
func (c *RemoteClient) readInitialEvent(ctx context.Context, br *bufio.Reader) error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- parseOneSSEEvent(ctx, br, func(ev shared.ConfigStreamEvent) {
			if err := applyEvent(c.reg, ev, nil); err != nil {
				slog.Warn("snapshot/remote: initial reload failed", "err", err)
			}
		})
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// consumeStreamReader drains SSE events from an already-wrapped
// bufio.Reader until EOF / error / ctx. Used by the initial-handoff
// branch of run() so the bytes that Start had buffered are still seen
// by the reconnect loop.
func (c *RemoteClient) consumeStreamReader(ctx context.Context, br *bufio.Reader) error {
	return parseSSEStreamBuffered(ctx, br, func(ev shared.ConfigStreamEvent) {
		if err := applyEvent(c.reg, ev, nil); err != nil {
			slog.Warn("snapshot/remote: reload failed", "err", err)
		}
	})
}

// connectAndConsume opens an SSE connection and drives parse+apply.
// Returns nil on clean shutdown via ctx, or an error describing the
// connection-terminating condition.
func (c *RemoteClient) connectAndConsume(ctx context.Context) error {
	resp, err := c.openStream(ctx)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return parseSSEStream(ctx, resp.Body, func(ev shared.ConfigStreamEvent) {
		if err := applyEvent(c.reg, ev, nil); err != nil {
			slog.Warn("snapshot/remote: reload failed", "err", err)
		}
	})
}

// streamURL returns the configured SSE endpoint. Test overrides take
// precedence over the bootstrap config so integration tests can point
// at httptest.NewServer URLs.
func (c *RemoteClient) streamURL() string {
	if c.streamURLOverride != "" {
		return c.streamURLOverride
	}
	if c.cfg == nil {
		return ""
	}
	base := strings.TrimRight(c.cfg.HubURL, "/")
	if base == "" {
		return ""
	}
	return base + "/v1/config/stream"
}

// parseSSEStream reads SSE frames from body and invokes onEvent for
// each parsed ConfigStreamEvent. It returns when body is exhausted or
// ctx is cancelled.
func parseSSEStream(ctx context.Context, body io.Reader, onEvent func(shared.ConfigStreamEvent)) error {
	return parseSSEStreamBuffered(ctx, bufio.NewReader(body), onEvent)
}

// parseSSEStreamBuffered is the bufio.Reader-aware variant. It is used
// by callers that have already wrapped the body (e.g. to read a single
// initial event before handing the buffered reader to a drain loop).
func parseSSEStreamBuffered(ctx context.Context, br *bufio.Reader, onEvent func(shared.ConfigStreamEvent)) error {
	return readSSEEvents(ctx, br, onEvent, -1)
}

// parseOneSSEEvent blocks until exactly one SSE event is parsed off br
// (or until ctx fires or the body is exhausted). It is the first-event
// helper used by Start to confirm the subscription before handing the
// body off to the reconnect loop. EOF before any event is treated as
// an error because it means the hub closed the stream with no data —
// Start must not return success in that case.
func parseOneSSEEvent(ctx context.Context, br *bufio.Reader, onEvent func(shared.ConfigStreamEvent)) error {
	var gotOne bool
	wrapped := func(ev shared.ConfigStreamEvent) {
		onEvent(ev)
		gotOne = true
	}
	err := readSSEEvents(ctx, br, wrapped, 1)
	if err != nil {
		return err
	}
	if !gotOne {
		return errors.New("stream closed before initial event")
	}
	return nil
}

// readSSEEvents is the shared low-level event loop. When maxEvents is
// non-negative, it returns after that many onEvent callbacks have
// fired; otherwise it drains until the body ends or ctx fires.
func readSSEEvents(ctx context.Context, br *bufio.Reader, onEvent func(shared.ConfigStreamEvent), maxEvents int) error {
	var (
		evType    string
		data      strings.Builder
		emitted   int
		stopAfter = maxEvents
	)
	flush := func() bool {
		if data.Len() == 0 {
			evType = ""
			data.Reset()
			return false
		}
		var ev shared.ConfigStreamEvent
		if err := json.Unmarshal([]byte(data.String()), &ev); err != nil {
			// Some SSE producers wrap just the payload into data; be
			// tolerant and fall back to synthesising an event from the
			// event type when the frame is not a full event JSON.
			if evType != "" {
				ev = shared.ConfigStreamEvent{
					Type: shared.ConfigStreamEventType(evType),
					Data: json.RawMessage(data.String()),
				}
			} else {
				evType = ""
				data.Reset()
				return false
			}
		}
		onEvent(ev)
		emitted++
		evType = ""
		data.Reset()
		return stopAfter >= 0 && emitted >= stopAfter
	}

	for {
		if ctx.Err() != nil {
			return nil
		}
		line, err := br.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				if len(line) > 0 {
					// Leftover without newline — treat as end-of-frame.
					handleSSELine(line, &evType, &data)
					flush()
				}
				return nil
			}
			return err
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			if flush() {
				return nil
			}
			continue
		}
		handleSSELine(trimmed, &evType, &data)
	}
}

// handleSSELine parses one SSE field line (key: value). Comments
// (prefixed with ":") and unknown fields are ignored.
func handleSSELine(line string, evType *string, data *strings.Builder) {
	if strings.HasPrefix(line, ":") {
		return
	}
	idx := strings.IndexByte(line, ':')
	if idx < 0 {
		return
	}
	key := line[:idx]
	val := line[idx+1:]
	if strings.HasPrefix(val, " ") {
		val = val[1:]
	}
	switch key {
	case "event":
		*evType = val
	case "data":
		if data.Len() > 0 {
			data.WriteByte('\n')
		}
		data.WriteString(val)
	}
}

// ---------------------------------------------------------------------
// Event application.

// applyEvent translates ev into a feature.Registry reload. When hreg is
// non-nil, it is used as the authoritative source for deltas (the event
// only tells us "something changed"; the live registry's Snapshot is
// the truth). When hreg is nil (remote mode), the event's payload is
// the authoritative source and is translated directly.
func applyEvent(reg *feature.Registry, ev shared.ConfigStreamEvent, hreg *hub.Registry) error {
	if reg == nil {
		return nil
	}
	var (
		globalsSnap feature.GlobalsSnapshot
		tenantsSnap map[string]feature.TenantSnapshot
		err         error
	)
	switch {
	case hreg != nil:
		globalsConf, tenantsConf := hreg.Snapshot()
		globalsSnap = translateGlobals(globalsConf)
		tenantsSnap = translateTenantsConf(tenantsConf)
	default:
		globalsSnap, tenantsSnap, err = translateEvent(ev, reg.Globals(), reg.Tenants())
		if err != nil {
			return err
		}
	}
	return reg.Reload(globalsSnap, tenantsSnap)
}

// translateEvent applies ev to the previously-known globals+tenants,
// returning the next full snapshot ready for feature.Registry.Reload.
// This is the remote-mode counterpart to hub.Registry.Snapshot in
// local mode.
func translateEvent(ev shared.ConfigStreamEvent, prevGlobals feature.GlobalsSnapshot, prevTenants map[string]feature.TenantSnapshot) (feature.GlobalsSnapshot, map[string]feature.TenantSnapshot, error) {
	// Defensive copies so we never mutate the registry's published map.
	nextG := feature.GlobalsSnapshot{Features: map[string]shared.FeatureSnapshot{}}
	for k, v := range prevGlobals.Features {
		nextG.Features[k] = v
	}
	nextT := make(map[string]feature.TenantSnapshot, len(prevTenants))
	for k, v := range prevTenants {
		ft := make(map[string]shared.FeatureSnapshot, len(v.Features))
		for fk, fv := range v.Features {
			ft[fk] = fv
		}
		nextT[k] = feature.TenantSnapshot{Host: v.Host, Enabled: v.Enabled, Features: ft}
	}

	switch ev.Type {
	case shared.EventSnapshot:
		var payload shared.SnapshotPayload
		if err := json.Unmarshal(ev.Data, &payload); err != nil {
			return nextG, nextT, fmt.Errorf("parse snapshot payload: %w", err)
		}
		nextG = translateGlobalsRaw(payload.Globals)
		nextT = map[string]feature.TenantSnapshot{}
		for _, ti := range payload.Tenants {
			nextT[strings.ToLower(ti.Host)] = tenantInfoToSnapshot(ti)
		}
	case shared.EventGlobalsUpdate:
		nextG = translateGlobalsRaw(ev.Data)
	case shared.EventTenantUpsert:
		var ti shared.TenantInfo
		if err := json.Unmarshal(ev.Data, &ti); err != nil {
			return nextG, nextT, fmt.Errorf("parse tenant upsert: %w", err)
		}
		nextT[strings.ToLower(ti.Host)] = tenantInfoToSnapshot(ti)
	case shared.EventTenantDelete:
		var payload shared.TenantDeletePayload
		if err := json.Unmarshal(ev.Data, &payload); err != nil {
			return nextG, nextT, fmt.Errorf("parse tenant delete: %w", err)
		}
		delete(nextT, strings.ToLower(payload.Host))
	default:
		// Unknown event types are tolerated silently so forward-compat
		// with future hub versions does not crash the edge.
	}
	return nextG, nextT, nil
}

// translateGlobals converts a config.GlobalsConf (the hub-side
// runtime file shape) into a feature.GlobalsSnapshot (the feature
// registry shape) without copying any more than necessary.
func translateGlobals(g config.GlobalsConf) feature.GlobalsSnapshot {
	out := feature.GlobalsSnapshot{Features: map[string]shared.FeatureSnapshot{}}
	for name, fc := range g.Features {
		out.Features[name] = shared.FeatureSnapshot{
			Enabled: fc.Enabled,
			Params:  copyParams(fc.Params),
		}
	}
	return out
}

// translateGlobalsRaw decodes the raw JSON globals payload carried on
// EventGlobalsUpdate / EventSnapshot frames. The hub emits it as
// encoded config.GlobalsConf, which we decode and run through the same
// translator as the fsnotify path.
func translateGlobalsRaw(raw json.RawMessage) feature.GlobalsSnapshot {
	if len(raw) == 0 {
		return feature.GlobalsSnapshot{Features: map[string]shared.FeatureSnapshot{}}
	}
	var g config.GlobalsConf
	if err := json.Unmarshal(raw, &g); err == nil && g.Features != nil {
		return translateGlobals(g)
	}
	// Fall back to feature.GlobalsSnapshot directly.
	var gs feature.GlobalsSnapshot
	if err := json.Unmarshal(raw, &gs); err == nil && gs.Features != nil {
		return gs
	}
	return feature.GlobalsSnapshot{Features: map[string]shared.FeatureSnapshot{}}
}

// translateTenantsConf converts the hub's TenantConf map into the
// feature-layer TenantSnapshot map.
func translateTenantsConf(ts map[string]config.TenantConf) map[string]feature.TenantSnapshot {
	out := make(map[string]feature.TenantSnapshot, len(ts))
	for host, t := range ts {
		feat := make(map[string]shared.FeatureSnapshot, len(t.Features))
		for name, fc := range t.Features {
			feat[name] = shared.FeatureSnapshot{
				Enabled: fc.Enabled,
				Params:  copyParams(fc.Params),
			}
		}
		out[strings.ToLower(host)] = feature.TenantSnapshot{
			Host:     strings.ToLower(t.Host),
			Enabled:  t.Enabled,
			Features: feat,
		}
	}
	return out
}

// tenantInfoToSnapshot converts the SSE TenantInfo payload into the
// feature-layer TenantSnapshot. The only lossy step is that we drop the
// backend list; backends are separately consumed by TorTransport.
func tenantInfoToSnapshot(ti shared.TenantInfo) feature.TenantSnapshot {
	feats := make(map[string]shared.FeatureSnapshot, len(ti.FeatureSnapshots))
	for name, fs := range ti.FeatureSnapshots {
		feats[name] = shared.FeatureSnapshot{
			Enabled: fs.Enabled,
			Params:  copyParams(fs.Params),
			Version: fs.Version,
		}
	}
	return feature.TenantSnapshot{
		Host:     strings.ToLower(ti.Host),
		Enabled:  ti.Enabled,
		Features: feats,
	}
}

// copyParams returns a shallow copy of p so that concurrent reloads
// cannot observe mid-mutation values. The nested map[string]any values
// are not deep-copied because feature.Validate must not mutate them.
func copyParams(p map[string]any) map[string]any {
	if p == nil {
		return nil
	}
	out := make(map[string]any, len(p))
	for k, v := range p {
		out[k] = v
	}
	return out
}
