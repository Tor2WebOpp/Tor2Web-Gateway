package hub

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

// Mirror-health storage lives under <data_dir>/runtime/mirrors/<host>.yaml.
// The layout is intentionally parallel to tenants/ so operators can inspect
// and edit mirror records with the same mental model.
const (
	runtimeDir     = "runtime"
	mirrorsSubdir  = "mirrors"
	settingsSubdir = "settings"
	mirrorExt      = ".yaml"

	// checkhostSettingsFile is the single YAML file under runtime/settings/
	// that persists the monitor's tunables (interval, regions, threshold,
	// etc.). It is read on every Monitor tick so operators can tweak the
	// schedule without restarting the hub.
	checkhostSettingsFile = "checkhost.yaml"
)

// Verdict enumerates the health classifications emitted by UpdateHealth.
// "unknown" covers freshly-registered mirrors that have never been checked.
type Verdict string

const (
	VerdictLive     Verdict = "live"
	VerdictDegraded Verdict = "degraded"
	VerdictBlocked  Verdict = "blocked"
	VerdictUnknown  Verdict = "unknown"
)

// RegionStatus is one vantage point's observation of a mirror. "Status" is a
// short tag drawn from the check-host.net client's vocabulary ("ok",
// "timeout", "refused", "error", "blocked-inferred"); "LatencyMs" is the
// round-trip time when Status=="ok" and 0 otherwise.
type RegionStatus struct {
	Status    string    `yaml:"status" json:"status"`
	LatencyMs int       `yaml:"latency_ms" json:"latency_ms"`
	At        time.Time `yaml:"at" json:"at"`
}

// MirrorHealth is the persisted per-mirror record. Regions is keyed on the
// check-host.net node identifier (or ISO 3166 alpha-2 when the caller maps
// them). Manual* fields let an operator force a mirror out of rotation even
// when the probe says it is live.
type MirrorHealth struct {
	Host          string                  `yaml:"host" json:"host"`
	LastCheck     time.Time               `yaml:"last_check" json:"last_check"`
	Regions       map[string]RegionStatus `yaml:"regions" json:"regions"`
	Verdict       Verdict                 `yaml:"verdict" json:"verdict"`
	BlockedCount  int                     `yaml:"blocked_count" json:"blocked_count"`
	TotalChecked  int                     `yaml:"total_checked" json:"total_checked"`
	ManualBlock   bool                    `yaml:"manual_block" json:"manual_block"`
	ManualNote    string                  `yaml:"manual_note,omitempty" json:"manual_note,omitempty"`
	Weight        int                     `yaml:"weight" json:"weight"`
	TargetTenants []string                `yaml:"target_tenants,omitempty" json:"target_tenants,omitempty"`
}

// CheckHostSettings captures the monitor tunables persisted under
// runtime/settings/checkhost.yaml. Defaults are applied by the Monitor, not
// here, so a missing field simply reads back as zero.
type CheckHostSettings struct {
	Enabled      bool          `yaml:"enabled" json:"enabled"`
	Interval     time.Duration `yaml:"interval" json:"interval"`
	Regions      []string      `yaml:"regions" json:"regions"`
	MaxNodes     int           `yaml:"max_nodes" json:"max_nodes"`
	ThresholdPct float64       `yaml:"threshold_pct" json:"threshold_pct"`
}

// MirrorRegistry is the authoritative, in-memory + on-disk view of every
// mirror domain the hub is tracking. It mirrors the Registry pattern for
// tenants: goroutine-safe, writes go to disk atomically before the in-memory
// map is touched, and the fsnotify watcher hot-reloads external edits.
//
// Subscribe reuses the package-level Subscriber interface so SSE consumers can
// accept either tenant or mirror events without a second abstraction. Events
// broadcast by MirrorRegistry are shaped by the caller — this package just
// passes them through.
type MirrorRegistry struct {
	dataDir    string
	mirrorsDir string

	mu       sync.RWMutex
	mirrors  map[string]MirrorHealth
	version  uint64
	closed   bool
	subID    atomic.Uint64
	subs     map[uint64]*mirrorSubState
	cancelFn context.CancelFunc

	logger *slog.Logger
}

// mirrorSubState is the per-subscriber queue. The structure is a drop-in copy
// of subState but specialised for MirrorEvent so the two registries stay
// decoupled. Overflow drops the oldest event so a slow peer cannot stall the
// hub's write path.
type mirrorSubState struct {
	id      uint64
	sub     MirrorSubscriber
	ch      chan MirrorEvent
	done    chan struct{}
	dropMu  sync.Mutex
	closeMu sync.Mutex
	closed  bool
}

// MirrorEventType enumerates the deltas broadcast from MirrorRegistry.
type MirrorEventType string

const (
	MirrorEventSnapshot MirrorEventType = "mirror_snapshot"
	MirrorEventUpsert   MirrorEventType = "mirror_upsert"
	MirrorEventDelete   MirrorEventType = "mirror_delete"
)

// MirrorEvent is the shape sent to subscribers. Snapshot carries the full
// list for bootstrap; Upsert carries one; Delete carries only the host.
type MirrorEvent struct {
	Type      MirrorEventType
	Mirrors   []MirrorHealth
	Mirror    MirrorHealth
	Host      string
	Timestamp time.Time
	Version   uint64
}

// MirrorSubscriber is the same pattern as Subscriber on Registry, but for
// MirrorEvent values. We keep it separate so callers can distinguish tenant
// streams from mirror streams by type.
type MirrorSubscriber interface {
	OnMirrorEvent(ev MirrorEvent)
}

// NewMirrors constructs a MirrorRegistry rooted at dataDir. The directory
// layout mirrors tenants/: dataDir/runtime/mirrors/<host>.yaml. Missing dirs
// are created with 0755; existing files are loaded eagerly so List returns a
// populated result immediately after construction. fsnotify starts in the
// background and surface-level errors are logged rather than fatal so the
// hub continues to serve API requests even if the watcher fails (the writes
// still go through atomicWrite, which is correct by itself).
func NewMirrors(dataDir string) (*MirrorRegistry, error) {
	if dataDir == "" {
		return nil, errors.New("hub mirrors: data_dir is required")
	}
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, fmt.Errorf("hub mirrors: abs %q: %w", dataDir, err)
	}
	mirrorsDir := filepath.Join(abs, runtimeDir, mirrorsSubdir)
	if err := os.MkdirAll(mirrorsDir, 0o755); err != nil {
		return nil, fmt.Errorf("hub mirrors: mkdir: %w", err)
	}
	// Settings dir is created eagerly so Save/Load can assume it exists.
	if err := os.MkdirAll(filepath.Join(abs, runtimeDir, settingsSubdir), 0o755); err != nil {
		return nil, fmt.Errorf("hub mirrors: mkdir settings: %w", err)
	}

	r := &MirrorRegistry{
		dataDir:    abs,
		mirrorsDir: mirrorsDir,
		mirrors:    make(map[string]MirrorHealth),
		subs:       make(map[uint64]*mirrorSubState),
		logger:     slog.Default().With("component", "hub.mirrors"),
	}
	if err := r.loadFromDisk(); err != nil {
		r.logger.Warn("hub mirrors: load-from-disk reported errors", "err", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	r.cancelFn = cancel
	if err := r.startWatcher(ctx); err != nil {
		cancel()
		return nil, fmt.Errorf("hub mirrors: start watcher: %w", err)
	}
	return r, nil
}

// MirrorsDir exposes the resolved on-disk directory — handy for tests.
func (r *MirrorRegistry) MirrorsDir() string { return r.mirrorsDir }

// DataDir returns the root data directory passed at construction.
func (r *MirrorRegistry) DataDir() string { return r.dataDir }

// List returns a deep copy of every mirror, sorted by host, so callers may
// mutate without racing the registry.
func (r *MirrorRegistry) List() []MirrorHealth {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]MirrorHealth, 0, len(r.mirrors))
	for _, m := range r.mirrors {
		out = append(out, cloneMirror(m))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

// Get looks up a mirror by host; ok=false when absent.
func (r *MirrorRegistry) Get(host string) (MirrorHealth, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.mirrors[host]
	if !ok {
		return MirrorHealth{}, false
	}
	return cloneMirror(m), true
}

// Upsert persists m to disk atomically, updates the in-memory map, and
// broadcasts an Upsert event. Unknown Verdict is coerced to VerdictUnknown.
// Weight defaults to 1 when zero so the door's weighted selector always has
// a positive divisor.
func (r *MirrorRegistry) Upsert(ctx context.Context, m MirrorHealth) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.Host == "" {
		return errors.New("hub mirrors: host is required")
	}
	if m.Verdict == "" {
		m.Verdict = VerdictUnknown
	}
	if m.Weight == 0 {
		m.Weight = 1
	}
	if err := r.writeMirror(m); err != nil {
		return err
	}

	r.mu.Lock()
	r.mirrors[m.Host] = cloneMirror(m)
	r.version++
	v := r.version
	r.mu.Unlock()

	r.broadcast(MirrorEvent{
		Type:      MirrorEventUpsert,
		Mirror:    cloneMirror(m),
		Host:      m.Host,
		Timestamp: time.Now().UTC(),
		Version:   v,
	})
	return nil
}

// Delete removes the mirror from disk and memory. Deleting an unknown host is
// idempotent: the disk remove is no-error for missing files, and no event is
// emitted when nothing changed.
func (r *MirrorRegistry) Delete(ctx context.Context, host string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if host == "" {
		return errors.New("hub mirrors: host is required")
	}
	if err := r.deleteMirrorFile(host); err != nil {
		return err
	}

	r.mu.Lock()
	_, existed := r.mirrors[host]
	delete(r.mirrors, host)
	if existed {
		r.version++
	}
	v := r.version
	r.mu.Unlock()

	if !existed {
		return nil
	}
	r.broadcast(MirrorEvent{
		Type:      MirrorEventDelete,
		Host:      host,
		Timestamp: time.Now().UTC(),
		Version:   v,
	})
	return nil
}

// ForceBlock marks the mirror as manually blocked. The verdict is pinned to
// VerdictBlocked until Unblock is called; UpdateHealth respects the flag and
// will not overwrite the verdict. An unknown host is auto-registered so an
// operator can pre-block a mirror that has not been probed yet.
func (r *MirrorRegistry) ForceBlock(ctx context.Context, host, note string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if host == "" {
		return errors.New("hub mirrors: host is required")
	}
	r.mu.Lock()
	m, ok := r.mirrors[host]
	if !ok {
		m = MirrorHealth{Host: host, Weight: 1}
	}
	m.ManualBlock = true
	m.ManualNote = note
	m.Verdict = VerdictBlocked
	r.mu.Unlock()
	return r.Upsert(ctx, m)
}

// Unblock clears the manual-block flag and note. The verdict is left as
// VerdictUnknown until the next health update so callers don't race against a
// stale "live" that was set before the manual block.
func (r *MirrorRegistry) Unblock(ctx context.Context, host string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if host == "" {
		return errors.New("hub mirrors: host is required")
	}
	r.mu.Lock()
	m, ok := r.mirrors[host]
	r.mu.Unlock()
	if !ok {
		return fmt.Errorf("hub mirrors: unknown host %q", host)
	}
	m.ManualBlock = false
	m.ManualNote = ""
	m.Verdict = VerdictUnknown
	return r.Upsert(ctx, m)
}

// UpdateHealth recomputes the verdict from regionResults using thresholdPct
// (e.g. 0.5 for 50%). Rules:
//   - >= threshold fraction fail (timeout/refused/error/blocked-inferred) → blocked
//   - 0 < fail fraction < threshold → degraded
//   - 0 failures → live
//   - empty results → verdict unchanged (still treated as a check; LastCheck
//     is refreshed)
//
// ManualBlock wins over whatever verdict this method would compute; the flag
// is the operator's kill-switch and is never overridden by a probe.
//
// Unknown hosts are auto-registered so the monitor can seed the registry on
// first run without a separate Upsert step.
func (r *MirrorRegistry) UpdateHealth(ctx context.Context, host string, regionResults map[string]RegionStatus, thresholdPct float64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if host == "" {
		return errors.New("hub mirrors: host is required")
	}

	r.mu.Lock()
	m, ok := r.mirrors[host]
	if !ok {
		m = MirrorHealth{Host: host, Weight: 1}
	}
	m.LastCheck = time.Now().UTC()
	if regionResults != nil {
		m.Regions = make(map[string]RegionStatus, len(regionResults))
		for k, v := range regionResults {
			m.Regions[k] = v
		}
	}

	total := len(regionResults)
	blocked := 0
	for _, rs := range regionResults {
		if statusIsFailure(rs.Status) {
			blocked++
		}
	}
	m.TotalChecked = total
	m.BlockedCount = blocked

	if m.ManualBlock {
		m.Verdict = VerdictBlocked
	} else if total == 0 {
		if m.Verdict == "" {
			m.Verdict = VerdictUnknown
		}
	} else {
		frac := float64(blocked) / float64(total)
		switch {
		case frac >= thresholdPct:
			m.Verdict = VerdictBlocked
		case blocked > 0:
			m.Verdict = VerdictDegraded
		default:
			m.Verdict = VerdictLive
		}
	}
	r.mu.Unlock()
	return r.Upsert(ctx, m)
}

// Subscribe registers s and immediately seeds it with a snapshot of all
// known mirrors. Returns an unsubscribe func that is safe to call multiple
// times. Event delivery is ordered per subscriber; overflow drops oldest.
func (r *MirrorRegistry) Subscribe(s MirrorSubscriber) func() {
	if s == nil {
		return func() {}
	}
	id := r.subID.Add(1)
	st := &mirrorSubState{
		id:   id,
		sub:  s,
		ch:   make(chan MirrorEvent, subBuffer),
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
	// Build the snapshot under the same lock so the caller can't race an
	// Upsert that would leave them with an event newer than their seed.
	mirrors := make([]MirrorHealth, 0, len(r.mirrors))
	for _, m := range r.mirrors {
		mirrors = append(mirrors, cloneMirror(m))
	}
	sort.Slice(mirrors, func(i, j int) bool { return mirrors[i].Host < mirrors[j].Host })
	version := r.version
	r.mu.Unlock()

	st.enqueue(MirrorEvent{
		Type:      MirrorEventSnapshot,
		Mirrors:   mirrors,
		Timestamp: time.Now().UTC(),
		Version:   version,
	})

	var once sync.Once
	return func() {
		once.Do(func() { r.removeSub(id) })
	}
}

// Close stops the fsnotify watcher and every subscriber drain goroutine. It
// is idempotent; calling it after a successful close is a no-op.
func (r *MirrorRegistry) Close() error {
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

// loadFromDisk scans the mirrors directory and rebuilds the in-memory map.
// Malformed files are logged and skipped so one bad write doesn't poison the
// whole registry. Bumps version so subscribers see a fresh cycle after a
// reload.
func (r *MirrorRegistry) loadFromDisk() error {
	entries, err := os.ReadDir(r.mirrorsDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	loaded := make(map[string]MirrorHealth)
	var errs []error
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), mirrorExt) {
			continue
		}
		full := filepath.Join(r.mirrorsDir, e.Name())
		m, err := readMirrorFile(full)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if m.Host == "" {
			continue
		}
		if m.Verdict == "" {
			m.Verdict = VerdictUnknown
		}
		if m.Weight == 0 {
			m.Weight = 1
		}
		loaded[m.Host] = m
	}
	r.mu.Lock()
	r.mirrors = loaded
	r.version++
	r.mu.Unlock()
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// writeMirror encodes m to YAML and writes it atomically. The host is
// sanitised for filesystem safety; the canonical value is preserved inside
// the YAML body.
func (r *MirrorRegistry) writeMirror(m MirrorHealth) error {
	data, err := yaml.Marshal(&m)
	if err != nil {
		return fmt.Errorf("hub mirrors: marshal %q: %w", m.Host, err)
	}
	return atomicWrite(r.mirrorPath(m.Host), data)
}

// deleteMirrorFile removes a single <host>.yaml. Missing is not an error.
func (r *MirrorRegistry) deleteMirrorFile(host string) error {
	p := r.mirrorPath(host)
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("hub mirrors: remove %q: %w", p, err)
	}
	return nil
}

func (r *MirrorRegistry) mirrorPath(host string) string {
	return filepath.Join(r.mirrorsDir, sanitizeHost(host)+mirrorExt)
}

// startWatcher starts an fsnotify goroutine that reloads on out-of-band file
// edits. Errors from the watcher are logged but not fatal — the registry's
// correctness lives in the mutative API, not the watcher.
func (r *MirrorRegistry) startWatcher(ctx context.Context) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("hub mirrors: fsnotify new: %w", err)
	}
	if err := w.Add(r.mirrorsDir); err != nil {
		_ = w.Close()
		return fmt.Errorf("hub mirrors: watch: %w", err)
	}

	go func() {
		defer w.Close()
		var (
			timer *time.Timer
			cbMu  sync.Mutex
		)
		for {
			select {
			case <-ctx.Done():
				if timer != nil {
					timer.Stop()
				}
				return
			case ev, ok := <-w.Events:
				if !ok {
					return
				}
				base := filepath.Base(ev.Name)
				if strings.HasPrefix(base, ".tmp-") {
					continue
				}
				if !strings.HasSuffix(strings.ToLower(base), mirrorExt) {
					continue
				}
				// Serialize the debounced callback: AfterFunc fires on
				// its own goroutine; an event landing mid-execution
				// would otherwise Reset() and schedule a concurrent
				// invocation that double-broadcasts mirror diffs.
				if timer == nil {
					timer = time.AfterFunc(watchDebounce, func() {
						cbMu.Lock()
						defer cbMu.Unlock()
						r.onExternalChange()
					})
				} else {
					timer.Stop()
					timer.Reset(watchDebounce)
				}
			case _, ok := <-w.Errors:
				if !ok {
					return
				}
			}
		}
	}()
	return nil
}

// onExternalChange reloads from disk and emits upsert events for the diff so
// subscribers observe the same stream regardless of whether the edit came
// through Upsert or an operator's text editor.
func (r *MirrorRegistry) onExternalChange() {
	r.mu.RLock()
	prev := make(map[string]MirrorHealth, len(r.mirrors))
	for k, v := range r.mirrors {
		prev[k] = cloneMirror(v)
	}
	r.mu.RUnlock()

	if err := r.loadFromDisk(); err != nil {
		r.logger.Warn("hub mirrors: external-change load failed", "err", err)
		return
	}

	r.mu.RLock()
	current := make(map[string]MirrorHealth, len(r.mirrors))
	for k, v := range r.mirrors {
		current[k] = cloneMirror(v)
	}
	version := r.version
	r.mu.RUnlock()

	// Upsert events for new or modified.
	hosts := make([]string, 0, len(current))
	for h := range current {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, h := range hosts {
		cur := current[h]
		if pv, ok := prev[h]; ok && mirrorEqual(pv, cur) {
			continue
		}
		r.broadcast(MirrorEvent{
			Type:      MirrorEventUpsert,
			Mirror:    cur,
			Host:      h,
			Timestamp: time.Now().UTC(),
			Version:   version,
		})
	}
	// Delete events for gone hosts.
	var gone []string
	for h := range prev {
		if _, still := current[h]; !still {
			gone = append(gone, h)
		}
	}
	sort.Strings(gone)
	for _, h := range gone {
		r.broadcast(MirrorEvent{
			Type:      MirrorEventDelete,
			Host:      h,
			Timestamp: time.Now().UTC(),
			Version:   version,
		})
	}
}

func (r *MirrorRegistry) broadcast(ev MirrorEvent) {
	r.mu.RLock()
	subs := make([]*mirrorSubState, 0, len(r.subs))
	for _, st := range r.subs {
		subs = append(subs, st)
	}
	r.mu.RUnlock()
	for _, st := range subs {
		st.enqueue(ev)
	}
}

func (r *MirrorRegistry) removeSub(id uint64) {
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

// enqueue delivers ev to this subscriber's queue. On overflow it drops the
// oldest event (never the new one) under dropMu so FIFO order is preserved.
// closeMu guards against racing an unsubscribe: once closed, later sends are
// silently dropped so the broadcaster never panics on a closed channel.
func (s *mirrorSubState) enqueue(ev MirrorEvent) {
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
			select {
			case <-s.ch:
			default:
			}
		}
	}
}

func (s *mirrorSubState) closeChan() {
	s.closeMu.Lock()
	if s.closed {
		s.closeMu.Unlock()
		return
	}
	s.closed = true
	close(s.ch)
	s.closeMu.Unlock()
}

func (s *mirrorSubState) drain() {
	defer close(s.done)
	for ev := range s.ch {
		s.sub.OnMirrorEvent(ev)
	}
}

// readMirrorFile loads one YAML file into a MirrorHealth.
func readMirrorFile(path string) (MirrorHealth, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return MirrorHealth{}, fmt.Errorf("hub mirrors: read %q: %w", path, err)
	}
	var m MirrorHealth
	if err := yaml.Unmarshal(data, &m); err != nil {
		return MirrorHealth{}, fmt.Errorf("hub mirrors: parse %q: %w", path, err)
	}
	return m, nil
}

// statusIsFailure reports whether a region's observed status should count
// against the verdict. Unknown statuses are treated as failures defensively.
func statusIsFailure(s string) bool {
	switch strings.ToLower(s) {
	case "ok", "":
		return s == ""
	default:
		return true
	}
}

// cloneMirror returns a deep-enough copy of m that callers may mutate the
// returned value without racing the registry.
func cloneMirror(m MirrorHealth) MirrorHealth {
	out := m
	if m.Regions != nil {
		out.Regions = make(map[string]RegionStatus, len(m.Regions))
		for k, v := range m.Regions {
			out.Regions[k] = v
		}
	}
	if m.TargetTenants != nil {
		out.TargetTenants = append([]string(nil), m.TargetTenants...)
	}
	return out
}

// mirrorEqual compares two MirrorHealth values via their YAML-encoded form.
// This matches the tenantEqual pattern in registry.go and sidesteps map-order
// issues in the Regions map.
func mirrorEqual(a, b MirrorHealth) bool {
	ab, errA := yaml.Marshal(a)
	bb, errB := yaml.Marshal(b)
	if errA != nil || errB != nil {
		return false
	}
	return string(ab) == string(bb)
}

// LoadCheckHostSettings reads the monitor settings from
// dataDir/runtime/settings/checkhost.yaml. Missing file returns a zero-value
// struct with no error — the Monitor supplies defaults.
func LoadCheckHostSettings(dataDir string) (CheckHostSettings, error) {
	p := settingsPath(dataDir)
	data, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return CheckHostSettings{}, nil
		}
		return CheckHostSettings{}, fmt.Errorf("hub mirrors: read settings: %w", err)
	}
	var s CheckHostSettings
	if err := yaml.Unmarshal(data, &s); err != nil {
		return CheckHostSettings{}, fmt.Errorf("hub mirrors: parse settings: %w", err)
	}
	return s, nil
}

// SaveCheckHostSettings persists s atomically. The parent directory is
// created on demand so callers don't have to guard against a fresh data dir.
func SaveCheckHostSettings(dataDir string, s CheckHostSettings) error {
	if err := os.MkdirAll(filepath.Join(dataDir, runtimeDir, settingsSubdir), 0o755); err != nil {
		return fmt.Errorf("hub mirrors: mkdir settings: %w", err)
	}
	data, err := yaml.Marshal(&s)
	if err != nil {
		return fmt.Errorf("hub mirrors: marshal settings: %w", err)
	}
	return atomicWrite(settingsPath(dataDir), data)
}

func settingsPath(dataDir string) string {
	return filepath.Join(dataDir, runtimeDir, settingsSubdir, checkhostSettingsFile)
}
