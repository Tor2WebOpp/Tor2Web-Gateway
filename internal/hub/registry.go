package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"

	"gateway/internal/config"
	"gateway/internal/shared"
)

// subBuffer bounds each subscriber's queued events. Events beyond the buffer
// cause the oldest event on that subscriber's queue to be dropped, not the
// new one: downstream consumers are interested in the latest state and should
// never block the hub's write path. 32 is deliberately small so tests can
// exercise the overflow path without flooding memory.
const subBuffer = 32

// Subscriber receives ordered config stream events. OnEvent must return
// promptly; slow subscribers are handled by dropping their oldest buffered
// event, never by blocking the broadcaster.
type Subscriber interface {
	OnEvent(ev shared.ConfigStreamEvent)
}

// Registry owns the authoritative view of all tenants plus the globals.yaml.
// Instances are safe for concurrent use. Construct with New; Close to stop
// the fsnotify watcher and drain subscriber goroutines.
type Registry struct {
	storage *Storage

	mu       sync.RWMutex
	globals  config.GlobalsConf
	tenants  map[string]config.TenantConf
	version  uint64
	closed   bool
	subID    atomic.Uint64
	subs     map[uint64]*subState
	cancelFn context.CancelFunc

	logger *slog.Logger
}

// subState is the internal per-subscriber queue. Each has its own goroutine
// draining events in FIFO order. Writes from the registry are serialised
// through subState's bounded channel; on overflow we drop the oldest event.
// dropMu serializes enqueue() with itself, and closeMu serializes enqueue()
// against the unsubscribe path so close(ch) cannot race with a pending send.
type subState struct {
	id      uint64
	sub     Subscriber
	ch      chan shared.ConfigStreamEvent
	done    chan struct{}
	dropMu  sync.Mutex
	closeMu sync.Mutex
	closed  bool
}

// New constructs a Registry rooted at dataDir. It creates the storage layout,
// loads any existing globals.yaml and tenant files, and starts the fsnotify
// watcher that reloads state on out-of-band edits. Load errors on individual
// tenant files are logged and those tenants are skipped; a failure reading
// globals.yaml aborts construction by bubbling through LoadFromDisk's warning.
func New(dataDir string) (*Registry, error) {
	st, err := NewStorage(dataDir)
	if err != nil {
		return nil, err
	}
	r := &Registry{
		storage: st,
		tenants: make(map[string]config.TenantConf),
		subs:    make(map[uint64]*subState),
		logger:  slog.Default().With("component", "hub.registry"),
	}
	if err := r.LoadFromDisk(); err != nil {
		// LoadFromDisk surfaces malformed tenant files; report them but keep
		// whatever parsed successfully so the hub still boots.
		r.logger.Warn("hub: load-from-disk reported errors", "err", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	r.cancelFn = cancel
	if err := st.Watch(ctx, r.onExternalChange); err != nil {
		cancel()
		return nil, fmt.Errorf("hub: start watcher: %w", err)
	}
	return r, nil
}

// LoadFromDisk replaces the in-memory state with whatever Storage.LoadAll
// returns. Intended as a hot-reload entry point; safe to call repeatedly.
// The version counter is bumped by one so subscribers can use it to detect
// churn even if the actual content happens to be equal.
func (r *Registry) LoadFromDisk() error {
	globals, tenants, err := r.storage.LoadAll()

	r.mu.Lock()
	r.globals = globals
	r.tenants = tenants
	r.version++
	r.mu.Unlock()

	return err
}

// Snapshot returns a deep copy of the current globals + tenants map so the
// caller can freely mutate its result without affecting registry state.
func (r *Registry) Snapshot() (config.GlobalsConf, map[string]config.TenantConf) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return cloneGlobals(r.globals), cloneTenants(r.tenants)
}

// Tenant looks up a tenant by host; ok=false when no such host is registered.
func (r *Registry) Tenant(host string) (config.TenantConf, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tenants[host]
	if !ok {
		return config.TenantConf{}, false
	}
	return cloneTenant(t), true
}

// UpsertTenant persists t to disk atomically, then updates the in-memory map,
// then broadcasts a tenant_upsert event. If the disk write fails, the
// in-memory map is untouched.
func (r *Registry) UpsertTenant(ctx context.Context, t config.TenantConf) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if t.Host == "" {
		return errors.New("hub: tenant host is required")
	}
	if err := r.storage.WriteTenant(t.Host, t); err != nil {
		return err
	}

	r.mu.Lock()
	r.tenants[t.Host] = t
	r.version++
	v := r.version
	r.mu.Unlock()

	ev, err := shared.NewTenantUpsertEvent(tenantInfoFrom(t, v))
	if err != nil {
		return fmt.Errorf("hub: encode upsert event: %w", err)
	}
	r.broadcast(ev)
	return nil
}

// DeleteTenant removes the tenant file, deletes the in-memory entry, and
// broadcasts a tenant_delete event. Deleting an unknown host is a no-op: the
// disk call still runs (idempotent) but no event is emitted and the version
// is not bumped.
func (r *Registry) DeleteTenant(ctx context.Context, host string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if host == "" {
		return errors.New("hub: host is required")
	}
	if err := r.storage.DeleteTenantFile(host); err != nil {
		return err
	}

	r.mu.Lock()
	_, existed := r.tenants[host]
	delete(r.tenants, host)
	if existed {
		r.version++
	}
	r.mu.Unlock()

	if !existed {
		return nil
	}
	ev, err := shared.NewTenantDeleteEvent(host)
	if err != nil {
		return fmt.Errorf("hub: encode delete event: %w", err)
	}
	r.broadcast(ev)
	return nil
}

// SetGlobals writes globals.yaml atomically, updates in-memory state, and
// broadcasts a globals_update event carrying the new globals as JSON.
func (r *Registry) SetGlobals(ctx context.Context, g config.GlobalsConf) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := r.storage.WriteGlobals(g); err != nil {
		return err
	}
	r.mu.Lock()
	r.globals = g
	r.version++
	r.mu.Unlock()

	raw, err := json.Marshal(g)
	if err != nil {
		return fmt.Errorf("hub: encode globals: %w", err)
	}
	r.broadcast(shared.NewGlobalsEvent(raw))
	return nil
}

// Subscribe registers s for future events. It immediately enqueues a snapshot
// event carrying the current globals + tenants so the subscriber observes a
// consistent starting point. The returned unsubscribe function removes the
// subscriber and stops its drain goroutine; it is safe to call multiple times.
//
// Events are delivered in order per subscriber. If a subscriber's bounded
// queue is full, the oldest event in that queue is discarded to make room for
// the new one — slow subscribers never block the hub.
func (r *Registry) Subscribe(s Subscriber) func() {
	if s == nil {
		return func() {}
	}
	id := r.subID.Add(1)
	st := &subState{
		id:   id,
		sub:  s,
		ch:   make(chan shared.ConfigStreamEvent, subBuffer),
		done: make(chan struct{}),
	}
	go st.drain()

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		st.closeChan()
		<-st.done
		return func() {}
	}
	r.subs[id] = st

	// Build the snapshot under the same lock so the caller cannot race
	// against a concurrent Upsert/Delete that would leave them with a
	// version < their seeded snapshot.
	tenants := make([]shared.TenantInfo, 0, len(r.tenants))
	for _, t := range r.tenants {
		tenants = append(tenants, tenantInfoFrom(t, r.version))
	}
	sort.Slice(tenants, func(i, j int) bool { return tenants[i].Host < tenants[j].Host })
	globalsJSON, _ := json.Marshal(r.globals)
	version := r.version
	r.mu.Unlock()

	ev, err := shared.NewSnapshotEvent(tenants, globalsJSON, version)
	if err == nil {
		st.enqueue(ev)
	}

	var once sync.Once
	return func() {
		once.Do(func() { r.removeSub(id) })
	}
}

// Close stops the fsnotify watcher and all subscriber drain goroutines. It is
// idempotent.
func (r *Registry) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	subs := r.subs
	r.subs = nil
	cancel := r.cancelFn
	r.cancelFn = nil
	r.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	for _, st := range subs {
		st.closeChan()
		<-st.done
	}
	return nil
}

// onExternalChange runs when fsnotify reports a file event under data dir. We
// reload from disk under the write lock, compute the diff against the previous
// state, and emit matching events so subscribers see the same stream
// regardless of whether the edit came through the API or a text editor.
func (r *Registry) onExternalChange() {
	prev := r.snapshotLocked()
	globals, tenants, err := r.storage.LoadAll()
	if err != nil {
		r.logger.Warn("hub: external-change load failed", "err", err)
		return
	}

	r.mu.Lock()
	r.globals = globals
	r.tenants = tenants
	r.version++
	v := r.version
	r.mu.Unlock()

	prevGlobals, _ := json.Marshal(prev.globals)
	curGlobals, _ := json.Marshal(globals)
	if string(prevGlobals) != string(curGlobals) {
		r.broadcast(shared.NewGlobalsEvent(curGlobals))
	}

	// Upsert events for new or modified tenants. Sort for deterministic
	// ordering so tests and subscribers see a stable sequence.
	hosts := make([]string, 0, len(tenants))
	for h := range tenants {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, host := range hosts {
		t := tenants[host]
		pt, existed := prev.tenants[host]
		if existed && tenantEqual(pt, t) {
			continue
		}
		ev, err := shared.NewTenantUpsertEvent(tenantInfoFrom(t, v))
		if err != nil {
			r.logger.Warn("hub: encode external upsert", "host", host, "err", err)
			continue
		}
		r.broadcast(ev)
	}

	// Delete events for tenants that vanished. Sort for determinism.
	var gone []string
	for host := range prev.tenants {
		if _, still := tenants[host]; still {
			continue
		}
		gone = append(gone, host)
	}
	sort.Strings(gone)
	for _, host := range gone {
		ev, err := shared.NewTenantDeleteEvent(host)
		if err != nil {
			r.logger.Warn("hub: encode external delete", "host", host, "err", err)
			continue
		}
		r.broadcast(ev)
	}
}

// snapshotLocked captures the current globals + tenants under the read lock.
// It is only used internally before overwriting state during a reload.
func (r *Registry) snapshotLocked() snapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return snapshot{
		globals: cloneGlobals(r.globals),
		tenants: cloneTenants(r.tenants),
	}
}

// broadcast fans ev out to every subscriber without holding the main mutex
// for the duration. Dispatch is non-blocking thanks to subState.enqueue.
func (r *Registry) broadcast(ev shared.ConfigStreamEvent) {
	r.mu.RLock()
	subs := make([]*subState, 0, len(r.subs))
	for _, st := range r.subs {
		subs = append(subs, st)
	}
	r.mu.RUnlock()

	for _, st := range subs {
		st.enqueue(ev)
	}
}

// removeSub unregisters a subscriber and waits for its drain goroutine to
// exit. Safe to call concurrently with broadcasts; an in-flight broadcast
// that grabbed this subscriber before removal simply delivers its last
// event and the drain then exits on channel close.
func (r *Registry) removeSub(id uint64) {
	r.mu.Lock()
	st, ok := r.subs[id]
	if ok {
		delete(r.subs, id)
	}
	r.mu.Unlock()
	if !ok {
		return
	}
	st.closeChan()
	<-st.done
}

// enqueue sends ev to the subscriber's queue. If the queue is full, the
// oldest queued event is dropped first to make room. dropMu makes the
// drop-then-send pair atomic against concurrent enqueues so FIFO ordering
// is preserved for each subscriber. closeMu ensures we do not send on a
// closed channel if an unsubscribe is in progress.
func (s *subState) enqueue(ev shared.ConfigStreamEvent) {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.closed {
		return
	}
	s.dropMu.Lock()
	defer s.dropMu.Unlock()
	for {
		select {
		case s.ch <- ev:
			return
		default:
			// Channel full: drop the oldest. If another goroutine already
			// drained one while we were deciding to drop, the next loop
			// iteration will find space.
			select {
			case <-s.ch:
			default:
			}
		}
	}
}

// closeChan marks the subscriber as closed and closes its event channel.
// After this returns no further enqueue() will deliver events, and the drain
// goroutine will exit once it sees the closed channel. Safe to call multiple
// times.
func (s *subState) closeChan() {
	s.closeMu.Lock()
	if s.closed {
		s.closeMu.Unlock()
		return
	}
	s.closed = true
	close(s.ch)
	s.closeMu.Unlock()
}

// drain delivers events in FIFO order until the channel is closed.
func (s *subState) drain() {
	defer close(s.done)
	for ev := range s.ch {
		s.sub.OnEvent(ev)
	}
}

// snapshot is a plain pair used for in-memory diffs during hot reloads.
type snapshot struct {
	globals config.GlobalsConf
	tenants map[string]config.TenantConf
}

// tenantInfoFrom projects a TenantConf into the external-facing TenantInfo
// shape used by events. Version tracks the registry's monotonic counter.
func tenantInfoFrom(t config.TenantConf, version uint64) shared.TenantInfo {
	refs := make([]shared.BackendRef, len(t.Backends))
	for i, b := range t.Backends {
		refs[i] = shared.BackendRef{OnionAddr: b.Addr, Weight: b.Weight}
	}
	feats := make(map[string]shared.FeatureSnapshot, len(t.Features))
	for name, f := range t.Features {
		feats[name] = shared.FeatureSnapshot{
			Enabled: f.Enabled,
			Params:  f.Params,
			Version: version,
		}
	}
	return shared.TenantInfo{
		Host:             t.Host,
		Enabled:          t.Enabled,
		Backends:         refs,
		FeatureSnapshots: feats,
		Version:          version,
	}
}

// cloneTenant returns a deep-enough copy of t to safely hand to a caller that
// may mutate maps/slices. Scalar fields are copied by value; slices and maps
// are duplicated.
func cloneTenant(t config.TenantConf) config.TenantConf {
	out := t
	if t.Backends != nil {
		out.Backends = append([]config.BackendConf(nil), t.Backends...)
	}
	if t.Features != nil {
		out.Features = make(map[string]config.FeatureConf, len(t.Features))
		for k, v := range t.Features {
			out.Features[k] = cloneFeature(v)
		}
	}
	if t.StealthHS.ClientAuths != nil {
		out.StealthHS.ClientAuths = append([]config.ClientAuthEntry(nil), t.StealthHS.ClientAuths...)
	}
	if t.AssignedNodes != nil {
		out.AssignedNodes = append([]string(nil), t.AssignedNodes...)
	}
	return out
}

func cloneTenants(m map[string]config.TenantConf) map[string]config.TenantConf {
	out := make(map[string]config.TenantConf, len(m))
	for k, v := range m {
		out[k] = cloneTenant(v)
	}
	return out
}

func cloneGlobals(g config.GlobalsConf) config.GlobalsConf {
	out := g
	if g.Features != nil {
		out.Features = make(map[string]config.FeatureConf, len(g.Features))
		for k, v := range g.Features {
			out.Features[k] = cloneFeature(v)
		}
	}
	if g.Headers.StripUpstream != nil {
		out.Headers.StripUpstream = append([]string(nil), g.Headers.StripUpstream...)
	}
	if g.Headers.AddDownstream != nil {
		out.Headers.AddDownstream = append([]config.HeaderRule(nil), g.Headers.AddDownstream...)
	}
	return out
}

func cloneFeature(f config.FeatureConf) config.FeatureConf {
	out := f
	if f.Params != nil {
		out.Params = make(map[string]any, len(f.Params))
		for k, v := range f.Params {
			out.Params[k] = v
		}
	}
	return out
}

// tenantEqual reports whether two TenantConf values should be treated as
// equivalent for event-diff purposes. We compare the JSON-encoded form so
// nested maps with equal content compare equal regardless of Go map order.
func tenantEqual(a, b config.TenantConf) bool {
	ab, errA := json.Marshal(a)
	bb, errB := json.Marshal(b)
	if errA != nil || errB != nil {
		return false
	}
	return string(ab) == string(bb)
}
