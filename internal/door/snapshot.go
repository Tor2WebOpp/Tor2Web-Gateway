package door

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
	"gateway/internal/shared"
	"gateway/internal/transport"
)

// SnapshotClient subscribes to the hub's /v1/config/stream, filters for
// mirror_* event types, and feeds UpdateMirrors/UpsertMirror/RemoveMirror
// calls into a Selector.
//
// Deliberately narrow: the door does not consume tenant or globals
// events, so snapshot_tenants / globals_update frames are quietly
// dropped rather than translated.
type SnapshotClient struct {
	cfg       *config.Config
	transport transport.Transport
	sel       *Selector

	// minBackoff and maxBackoff pace reconnection attempts. Exposed as
	// package-private fields so tests can shorten them without racing
	// real-time timers.
	minBackoff     time.Duration
	maxBackoff     time.Duration
	initialTimeout time.Duration

	streamURLOverride string

	mu         sync.Mutex
	cancelFn   context.CancelFunc
	cancelDone chan struct{}
	closeOnce  sync.Once
}

// NewSnapshotClient builds a door-side snapshot client. t.AdminClient()
// is used when non-nil; otherwise http.DefaultClient fills in so tests
// that do not need a real transport can still construct the client.
func NewSnapshotClient(cfg *config.Config, t transport.Transport, sel *Selector) *SnapshotClient {
	return &SnapshotClient{
		cfg:            cfg,
		transport:      t,
		sel:            sel,
		minBackoff:     500 * time.Millisecond,
		maxBackoff:     30 * time.Second,
		initialTimeout: 10 * time.Second,
	}
}

// SetStreamURL overrides the SSE endpoint. Intended for tests.
func (c *SnapshotClient) SetStreamURL(u string) { c.streamURLOverride = u }

// Start performs a synchronous first connect and drains the initial
// mirror_snapshot event before returning. If the hub never sends a
// mirror_snapshot (old hub, or mirror-health registry disabled) the
// first non-mirror event satisfies the bootstrap — the Selector is
// simply left empty until the next reconnect.
//
// On first-connect failure (hub unreachable, non-200 status) Start
// returns an error without spawning the reconnect goroutine. Callers
// use that to distinguish bootstrap problems from post-boot churn.
func (c *SnapshotClient) Start(ctx context.Context) error {
	timeout := c.initialTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	attemptCtx, attemptCancel := context.WithTimeout(ctx, timeout)
	resp, err := c.openStream(attemptCtx)
	if err != nil {
		attemptCancel()
		return fmt.Errorf("door/snapshot: initial connect: %w", err)
	}
	br := bufio.NewReader(resp.Body)
	// Read exactly one event (any kind) so Start returns only after the
	// subscription is confirmed by the server.
	if err := readOneEvent(attemptCtx, br, func(ev shared.ConfigStreamEvent) {
		c.apply(ev)
	}); err != nil {
		resp.Body.Close()
		attemptCancel()
		return fmt.Errorf("door/snapshot: initial event: %w", err)
	}
	attemptCancel()

	c.mu.Lock()
	runCtx, cancel := context.WithCancel(ctx)
	c.cancelFn = cancel
	c.cancelDone = make(chan struct{})
	c.mu.Unlock()

	go c.run(runCtx, resp, br)
	return nil
}

// Close stops the reconnect loop. Safe to call multiple times.
func (c *SnapshotClient) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		cancel := c.cancelFn
		done := c.cancelDone
		c.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		if done != nil {
			<-done
		}
	})
	return nil
}

// run is the reconnect loop. The first iteration drains the already-
// open body Start left behind; subsequent iterations open fresh
// connections with exponential backoff.
func (c *SnapshotClient) run(ctx context.Context, initial *http.Response, buffered *bufio.Reader) {
	defer close(c.cancelDone)

	backoff := c.minBackoff

	if initial != nil {
		err := readAllEvents(ctx, buffered, func(ev shared.ConfigStreamEvent) {
			c.apply(ev)
		})
		initial.Body.Close()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			slog.Warn("door/snapshot: stream disconnected", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = nextBackoff(backoff, c.maxBackoff)
	}

	for {
		if ctx.Err() != nil {
			return
		}
		if err := c.connectAndConsume(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("door/snapshot: stream disconnected", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = nextBackoff(backoff, c.maxBackoff)
	}
}

// connectAndConsume opens an SSE connection, drains it until it ends
// or ctx fires, and returns the terminating error.
func (c *SnapshotClient) connectAndConsume(ctx context.Context) error {
	resp, err := c.openStream(ctx)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return readAllEvents(ctx, bufio.NewReader(resp.Body), func(ev shared.ConfigStreamEvent) {
		c.apply(ev)
	})
}

// apply routes ev into Selector updates. Non-mirror events (tenant,
// globals, unknown) are dropped silently: the door only cares about
// mirror health. An unparseable mirror event is logged at DEBUG only so
// a malformed frame cannot flood INFO-level logs.
func (c *SnapshotClient) apply(ev shared.ConfigStreamEvent) {
	switch ev.Type {
	case shared.EventMirrorSnapshot:
		var payload shared.MirrorSnapshotPayload
		if err := json.Unmarshal(ev.Data, &payload); err != nil {
			slog.Debug("door/snapshot: bad mirror_snapshot payload", "err", err)
			return
		}
		c.sel.UpdateMirrors(payload.Mirrors)
	case shared.EventMirrorUpsert:
		var m shared.MirrorInfo
		if err := json.Unmarshal(ev.Data, &m); err != nil {
			slog.Debug("door/snapshot: bad mirror_upsert payload", "err", err)
			return
		}
		c.sel.UpsertMirror(m)
	case shared.EventMirrorDelete:
		var payload shared.MirrorDeletePayload
		if err := json.Unmarshal(ev.Data, &payload); err != nil {
			slog.Debug("door/snapshot: bad mirror_delete payload", "err", err)
			return
		}
		c.sel.RemoveMirror(payload.Host)
	default:
		// tenant_upsert / tenant_delete / globals_update / snapshot
		// frames are irrelevant to doors.
	}
}

// openStream performs an HTTP GET against the hub SSE endpoint.
func (c *SnapshotClient) openStream(ctx context.Context) (*http.Response, error) {
	url := c.streamURL()
	if url == "" {
		return nil, errors.New("door/snapshot: hub URL is empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("door/snapshot: build request: %w", err)
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
		return nil, fmt.Errorf("door/snapshot: hub stream status %d", resp.StatusCode)
	}
	return resp, nil
}

// streamURL returns the SSE endpoint. Test overrides take precedence
// over cfg.HubURL so httptest.Server URLs can be dropped in.
func (c *SnapshotClient) streamURL() string {
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

// nextBackoff doubles cur up to max.
func nextBackoff(cur, max time.Duration) time.Duration {
	cur *= 2
	if cur > max {
		return max
	}
	return cur
}

// readOneEvent blocks until exactly one SSE event is parsed or ctx
// fires. EOF before any event yields an error.
func readOneEvent(ctx context.Context, br *bufio.Reader, onEvent func(shared.ConfigStreamEvent)) error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- parseSSE(ctx, br, onEvent, 1)
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// readAllEvents drains events until br ends or ctx fires.
func readAllEvents(ctx context.Context, br *bufio.Reader, onEvent func(shared.ConfigStreamEvent)) error {
	return parseSSE(ctx, br, onEvent, -1)
}

// parseSSE implements a minimal SSE parser. It understands "event:" and
// "data:" field lines, ignores comments, and emits one onEvent callback
// per blank-line-terminated frame. maxEvents < 0 drains until EOF.
func parseSSE(ctx context.Context, br *bufio.Reader, onEvent func(shared.ConfigStreamEvent), maxEvents int) error {
	var (
		evType    string
		data      strings.Builder
		emitted   int
		stopAfter = maxEvents
	)
	flush := func() (done, got bool) {
		if data.Len() == 0 {
			evType = ""
			data.Reset()
			return false, false
		}
		var ev shared.ConfigStreamEvent
		if err := json.Unmarshal([]byte(data.String()), &ev); err != nil {
			// Tolerant fallback: if the data frame isn't a complete
			// ConfigStreamEvent JSON, synthesize from event type.
			if evType != "" {
				ev = shared.ConfigStreamEvent{
					Type: shared.ConfigStreamEventType(evType),
					Data: json.RawMessage(data.String()),
				}
			} else {
				evType = ""
				data.Reset()
				return false, false
			}
		}
		onEvent(ev)
		emitted++
		evType = ""
		data.Reset()
		return stopAfter >= 0 && emitted >= stopAfter, true
	}

	for {
		if ctx.Err() != nil {
			return nil
		}
		line, err := br.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				if len(line) > 0 {
					handleLine(line, &evType, &data)
					flush()
				}
				if stopAfter >= 0 && emitted < stopAfter {
					return errors.New("stream closed before event")
				}
				return nil
			}
			return err
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			done, _ := flush()
			if done {
				return nil
			}
			continue
		}
		handleLine(trimmed, &evType, &data)
	}
}

// handleLine parses one SSE key:value field. Comments (lines starting
// with ":") and unknown keys are ignored.
func handleLine(line string, evType *string, data *strings.Builder) {
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
