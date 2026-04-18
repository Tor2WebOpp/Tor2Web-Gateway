package hub

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// recordingMirrorSub captures OnMirrorEvent calls for assertions.
type recordingMirrorSub struct {
	mu     sync.Mutex
	events []MirrorEvent
	delay  time.Duration
}

func (r *recordingMirrorSub) OnMirrorEvent(ev MirrorEvent) {
	if r.delay > 0 {
		time.Sleep(r.delay)
	}
	r.mu.Lock()
	r.events = append(r.events, ev)
	r.mu.Unlock()
}

func (r *recordingMirrorSub) snapshot() []MirrorEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]MirrorEvent, len(r.events))
	copy(out, r.events)
	return out
}

func (r *recordingMirrorSub) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

func waitForMirrorEvents(t *testing.T, sub *recordingMirrorSub, n int, timeout time.Duration) []MirrorEvent {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if sub.len() >= n {
			return sub.snapshot()
		}
		time.Sleep(10 * time.Millisecond)
	}
	return sub.snapshot()
}

func mustMirrors(t *testing.T) (*MirrorRegistry, string) {
	t.Helper()
	dir := t.TempDir()
	r, err := NewMirrors(dir)
	if err != nil {
		t.Fatalf("NewMirrors: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r, dir
}

func sampleMirror(host string) MirrorHealth {
	return MirrorHealth{
		Host:    host,
		Verdict: VerdictUnknown,
		Weight:  1,
	}
}

func TestNewMirrors_FreshDir(t *testing.T) {
	r, dir := mustMirrors(t)
	if got := r.List(); len(got) != 0 {
		t.Fatalf("expected 0 mirrors, got %d", len(got))
	}
	if _, err := os.Stat(filepath.Join(dir, runtimeDir, mirrorsSubdir)); err != nil {
		t.Fatalf("mirrors dir not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, runtimeDir, settingsSubdir)); err != nil {
		t.Fatalf("settings dir not created: %v", err)
	}
}

func TestNewMirrors_EmptyDir(t *testing.T) {
	if _, err := NewMirrors(""); err == nil {
		t.Fatal("expected error for empty data_dir")
	}
}

func TestMirrors_Upsert_RoundTrip(t *testing.T) {
	r, dir := mustMirrors(t)
	ctx := context.Background()
	m := sampleMirror("a.example.com")
	m.TargetTenants = []string{"tenant1.tld"}
	if err := r.Upsert(ctx, m); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	got, ok := r.Get("a.example.com")
	if !ok {
		t.Fatal("Get missed")
	}
	if got.Host != "a.example.com" || got.Weight != 1 || got.Verdict != VerdictUnknown {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	// File persisted.
	if _, err := os.Stat(filepath.Join(dir, runtimeDir, mirrorsSubdir, "a.example.com.yaml")); err != nil {
		t.Fatalf("file missing: %v", err)
	}
	// Mutating the returned value must not affect the registry state.
	got.TargetTenants[0] = "mutated"
	got2, _ := r.Get("a.example.com")
	if got2.TargetTenants[0] != "tenant1.tld" {
		t.Fatalf("mutation leaked back into registry: %+v", got2)
	}
}

func TestMirrors_Upsert_EmptyHost(t *testing.T) {
	r, _ := mustMirrors(t)
	if err := r.Upsert(context.Background(), MirrorHealth{}); err == nil {
		t.Fatal("expected error for empty host")
	}
}

func TestMirrors_Upsert_CancelledCtx(t *testing.T) {
	r, _ := mustMirrors(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.Upsert(ctx, sampleMirror("c.example.com")); err == nil {
		t.Fatal("expected error for cancelled ctx")
	}
}

func TestMirrors_Delete_Existing(t *testing.T) {
	r, dir := mustMirrors(t)
	ctx := context.Background()
	if err := r.Upsert(ctx, sampleMirror("gone.example.com")); err != nil {
		t.Fatal(err)
	}
	if err := r.Delete(ctx, "gone.example.com"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := r.Get("gone.example.com"); ok {
		t.Fatal("mirror still present after delete")
	}
	if _, err := os.Stat(filepath.Join(dir, runtimeDir, mirrorsSubdir, "gone.example.com.yaml")); !os.IsNotExist(err) {
		t.Fatalf("file still present: %v", err)
	}
}

func TestMirrors_Delete_Unknown(t *testing.T) {
	r, _ := mustMirrors(t)
	if err := r.Delete(context.Background(), "nope.example.com"); err != nil {
		t.Fatalf("Delete unknown returned error: %v", err)
	}
}

func TestMirrors_ForceBlock_UnblockLifecycle(t *testing.T) {
	r, _ := mustMirrors(t)
	ctx := context.Background()
	// Pre-seed with a live mirror.
	m := sampleMirror("f.example.com")
	m.Verdict = VerdictLive
	if err := r.Upsert(ctx, m); err != nil {
		t.Fatal(err)
	}
	if err := r.ForceBlock(ctx, "f.example.com", "operator note"); err != nil {
		t.Fatalf("ForceBlock: %v", err)
	}
	got, _ := r.Get("f.example.com")
	if !got.ManualBlock {
		t.Fatal("ManualBlock flag not set")
	}
	if got.Verdict != VerdictBlocked {
		t.Fatalf("Verdict = %q, want blocked", got.Verdict)
	}
	if got.ManualNote != "operator note" {
		t.Fatalf("ManualNote = %q", got.ManualNote)
	}

	// Unblock clears the flag but leaves verdict at unknown so the next
	// probe can re-classify.
	if err := r.Unblock(ctx, "f.example.com"); err != nil {
		t.Fatalf("Unblock: %v", err)
	}
	got, _ = r.Get("f.example.com")
	if got.ManualBlock {
		t.Fatal("ManualBlock still set after Unblock")
	}
	if got.Verdict != VerdictUnknown {
		t.Fatalf("Verdict after Unblock = %q, want unknown", got.Verdict)
	}
}

func TestMirrors_ForceBlock_AutoCreates(t *testing.T) {
	// Force-blocking an unknown host should auto-register it so operators
	// can pre-block a mirror before it's been probed.
	r, _ := mustMirrors(t)
	if err := r.ForceBlock(context.Background(), "new.example.com", ""); err != nil {
		t.Fatalf("ForceBlock: %v", err)
	}
	got, ok := r.Get("new.example.com")
	if !ok {
		t.Fatal("mirror not created")
	}
	if !got.ManualBlock || got.Verdict != VerdictBlocked {
		t.Fatalf("unexpected state: %+v", got)
	}
}

func TestMirrors_Unblock_UnknownHost(t *testing.T) {
	r, _ := mustMirrors(t)
	if err := r.Unblock(context.Background(), "nothere.example.com"); err == nil {
		t.Fatal("expected error unblocking unknown host")
	}
}

func TestMirrors_UpdateHealth_Live(t *testing.T) {
	r, _ := mustMirrors(t)
	ctx := context.Background()
	results := map[string]RegionStatus{
		"node1": {Status: "ok", LatencyMs: 120},
		"node2": {Status: "ok", LatencyMs: 80},
	}
	if err := r.UpdateHealth(ctx, "live.example.com", results, 0.5); err != nil {
		t.Fatalf("UpdateHealth: %v", err)
	}
	got, ok := r.Get("live.example.com")
	if !ok {
		t.Fatal("mirror not auto-created")
	}
	if got.Verdict != VerdictLive {
		t.Fatalf("Verdict = %q, want live", got.Verdict)
	}
	if got.BlockedCount != 0 || got.TotalChecked != 2 {
		t.Fatalf("counters wrong: %+v", got)
	}
}

func TestMirrors_UpdateHealth_Degraded(t *testing.T) {
	// 2 of 5 fail (40%) with threshold 50% -> degraded.
	r, _ := mustMirrors(t)
	results := map[string]RegionStatus{
		"a": {Status: "ok"},
		"b": {Status: "ok"},
		"c": {Status: "ok"},
		"d": {Status: "timeout"},
		"e": {Status: "refused"},
	}
	if err := r.UpdateHealth(context.Background(), "deg.example.com", results, 0.5); err != nil {
		t.Fatal(err)
	}
	got, _ := r.Get("deg.example.com")
	if got.Verdict != VerdictDegraded {
		t.Fatalf("Verdict = %q, want degraded (blocked=%d, total=%d)", got.Verdict, got.BlockedCount, got.TotalChecked)
	}
	if got.BlockedCount != 2 || got.TotalChecked != 5 {
		t.Fatalf("counters: %+v", got)
	}
}

func TestMirrors_UpdateHealth_Blocked(t *testing.T) {
	// 3 of 5 fail (60%) with threshold 50% -> blocked.
	r, _ := mustMirrors(t)
	results := map[string]RegionStatus{
		"a": {Status: "ok"},
		"b": {Status: "ok"},
		"c": {Status: "timeout"},
		"d": {Status: "refused"},
		"e": {Status: "error"},
	}
	if err := r.UpdateHealth(context.Background(), "blk.example.com", results, 0.5); err != nil {
		t.Fatal(err)
	}
	got, _ := r.Get("blk.example.com")
	if got.Verdict != VerdictBlocked {
		t.Fatalf("Verdict = %q, want blocked (%d/%d)", got.Verdict, got.BlockedCount, got.TotalChecked)
	}
}

func TestMirrors_UpdateHealth_ManualBlockWins(t *testing.T) {
	// With manual block set, a perfectly healthy probe must not flip the
	// verdict back to live.
	r, _ := mustMirrors(t)
	ctx := context.Background()
	if err := r.ForceBlock(ctx, "m.example.com", "kill"); err != nil {
		t.Fatal(err)
	}
	results := map[string]RegionStatus{
		"a": {Status: "ok"},
		"b": {Status: "ok"},
	}
	if err := r.UpdateHealth(ctx, "m.example.com", results, 0.5); err != nil {
		t.Fatal(err)
	}
	got, _ := r.Get("m.example.com")
	if got.Verdict != VerdictBlocked {
		t.Fatalf("Verdict = %q, want blocked (manual)", got.Verdict)
	}
	if !got.ManualBlock {
		t.Fatal("ManualBlock got cleared")
	}
}

func TestMirrors_UpdateHealth_EmptyResults(t *testing.T) {
	r, _ := mustMirrors(t)
	if err := r.UpdateHealth(context.Background(), "empty.example.com", nil, 0.5); err != nil {
		t.Fatal(err)
	}
	got, _ := r.Get("empty.example.com")
	if got.Verdict != VerdictUnknown {
		t.Fatalf("Verdict = %q, want unknown", got.Verdict)
	}
	if got.LastCheck.IsZero() {
		t.Fatal("LastCheck not updated")
	}
}

func TestMirrors_List_Sorted(t *testing.T) {
	r, _ := mustMirrors(t)
	ctx := context.Background()
	hosts := []string{"c.com", "a.com", "b.com"}
	for _, h := range hosts {
		if err := r.Upsert(ctx, sampleMirror(h)); err != nil {
			t.Fatal(err)
		}
	}
	list := r.List()
	if len(list) != 3 {
		t.Fatalf("len = %d", len(list))
	}
	want := []string{"a.com", "b.com", "c.com"}
	for i, m := range list {
		if m.Host != want[i] {
			t.Fatalf("list[%d].Host = %q, want %q", i, m.Host, want[i])
		}
	}
}

func TestMirrors_Subscribe_SnapshotAndDeltas(t *testing.T) {
	r, _ := mustMirrors(t)
	ctx := context.Background()
	// Seed one mirror so the snapshot has content.
	if err := r.Upsert(ctx, sampleMirror("seed.example.com")); err != nil {
		t.Fatal(err)
	}

	sub := &recordingMirrorSub{}
	unsub := r.Subscribe(sub)
	defer unsub()

	evts := waitForMirrorEvents(t, sub, 1, time.Second)
	if len(evts) == 0 {
		t.Fatal("no initial snapshot event")
	}
	if evts[0].Type != MirrorEventSnapshot {
		t.Fatalf("first event = %q, want snapshot", evts[0].Type)
	}
	if len(evts[0].Mirrors) != 1 || evts[0].Mirrors[0].Host != "seed.example.com" {
		t.Fatalf("snapshot contents: %+v", evts[0].Mirrors)
	}

	if err := r.Upsert(ctx, sampleMirror("second.example.com")); err != nil {
		t.Fatal(err)
	}
	evts = waitForMirrorEvents(t, sub, 2, time.Second)
	if len(evts) < 2 || evts[1].Type != MirrorEventUpsert {
		t.Fatalf("expected upsert event, got %+v", evts)
	}

	if err := r.Delete(ctx, "second.example.com"); err != nil {
		t.Fatal(err)
	}
	evts = waitForMirrorEvents(t, sub, 3, time.Second)
	if len(evts) < 3 || evts[2].Type != MirrorEventDelete {
		t.Fatalf("expected delete event, got %+v", evts)
	}
	if evts[2].Host != "second.example.com" {
		t.Fatalf("delete host = %q", evts[2].Host)
	}
}

func TestMirrors_Subscribe_Unsubscribe(t *testing.T) {
	r, _ := mustMirrors(t)
	sub := &recordingMirrorSub{}
	unsub := r.Subscribe(sub)
	waitForMirrorEvents(t, sub, 1, time.Second)
	unsub()
	unsub() // idempotent

	if err := r.Upsert(context.Background(), sampleMirror("late.example.com")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if sub.len() > 1 {
		t.Fatalf("events delivered after unsubscribe: %d", sub.len())
	}
}

func TestMirrors_Close_Idempotent(t *testing.T) {
	r, _ := mustMirrors(t)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestMirrors_Subscribe_AfterClose(t *testing.T) {
	r, _ := mustMirrors(t)
	_ = r.Close()
	sub := &recordingMirrorSub{}
	unsub := r.Subscribe(sub)
	unsub()
}

func TestMirrors_ConcurrentSubscribeAndUpsert(t *testing.T) {
	// Aim of this test is to trip the race detector if anything is wrong
	// with the locking around subs map + broadcast + enqueue.
	r, _ := mustMirrors(t)
	ctx := context.Background()

	const nSubs = 8
	const nUpserts = 30

	subs := make([]*recordingMirrorSub, nSubs)
	unsubs := make([]func(), nSubs)
	for i := 0; i < nSubs; i++ {
		subs[i] = &recordingMirrorSub{}
		unsubs[i] = r.Subscribe(subs[i])
	}
	defer func() {
		for _, u := range unsubs {
			u()
		}
	}()

	var wg sync.WaitGroup
	var started atomic.Int32
	start := make(chan struct{})
	for i := 0; i < nUpserts; i++ {
		wg.Add(1)
		host := fmt.Sprintf("c-%03d.example.com", i)
		go func(h string) {
			defer wg.Done()
			started.Add(1)
			<-start
			if err := r.Upsert(ctx, sampleMirror(h)); err != nil {
				t.Errorf("upsert: %v", err)
			}
		}(host)
	}
	for started.Load() < nUpserts {
		time.Sleep(time.Millisecond)
	}
	close(start)
	wg.Wait()

	if got := r.List(); len(got) != nUpserts {
		t.Fatalf("len = %d, want %d", len(got), nUpserts)
	}
}

func TestMirrors_SlowSubscriber_DoesNotBlock(t *testing.T) {
	r, _ := mustMirrors(t)
	slow := &recordingMirrorSub{delay: 50 * time.Millisecond}
	unsub := r.Subscribe(slow)
	defer unsub()
	fast := &recordingMirrorSub{}
	unsubFast := r.Subscribe(fast)
	defer unsubFast()

	const n = subBuffer * 3
	ctx := context.Background()
	deadline := time.After(5 * time.Second)
	done := make(chan struct{})
	go func() {
		for i := 0; i < n; i++ {
			_ = r.Upsert(ctx, sampleMirror(fmt.Sprintf("slow-%03d.example.com", i)))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-deadline:
		t.Fatal("hub blocked by slow subscriber")
	}

	evts := waitForMirrorEvents(t, fast, 1+n, 5*time.Second)
	if len(evts) < 1+n {
		t.Fatalf("fast subscriber saw %d events, want %d", len(evts), 1+n)
	}
}

func TestMirrors_ExternalFileWrite_TriggersReload(t *testing.T) {
	r, dir := mustMirrors(t)

	sub := &recordingMirrorSub{}
	unsub := r.Subscribe(sub)
	defer unsub()
	waitForMirrorEvents(t, sub, 1, time.Second)

	m := MirrorHealth{
		Host:    "ext.example.com",
		Verdict: VerdictLive,
		Weight:  1,
	}
	data, err := yaml.Marshal(&m)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, runtimeDir, mirrorsSubdir, "ext.example.com.yaml")
	if err := atomicWrite(path, data); err != nil {
		t.Fatalf("atomicWrite: %v", err)
	}

	// Debounce is 300ms; give up to 1.5s for the reload.
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, ok := r.Get("ext.example.com"); ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, ok := r.Get("ext.example.com"); !ok {
		t.Fatal("external write did not reload")
	}
}

func TestMirrors_LoadFromDiskOnConstruction(t *testing.T) {
	dir := t.TempDir()
	// Pre-seed a file before constructing.
	mirrorsDir := filepath.Join(dir, runtimeDir, mirrorsSubdir)
	if err := os.MkdirAll(mirrorsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	m := MirrorHealth{Host: "preseed.example.com", Verdict: VerdictLive, Weight: 2}
	data, err := yaml.Marshal(&m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mirrorsDir, "preseed.example.com.yaml"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := NewMirrors(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got, ok := r.Get("preseed.example.com")
	if !ok {
		t.Fatal("not loaded from disk")
	}
	if got.Weight != 2 || got.Verdict != VerdictLive {
		t.Fatalf("load mismatch: %+v", got)
	}
}

func TestCheckHostSettings_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	// Load from empty dir must be no-error zero.
	s, err := LoadCheckHostSettings(dir)
	if err != nil {
		t.Fatalf("Load empty: %v", err)
	}
	if s.Enabled || s.Interval != 0 || s.MaxNodes != 0 || s.ThresholdPct != 0 || len(s.Regions) != 0 {
		t.Fatalf("expected zero, got %+v", s)
	}
	want := CheckHostSettings{
		Enabled:      true,
		Interval:     5 * time.Minute,
		Regions:      []string{"us1", "de1"},
		MaxNodes:     5,
		ThresholdPct: 0.4,
	}
	if err := SaveCheckHostSettings(dir, want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := LoadCheckHostSettings(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Enabled != want.Enabled || got.Interval != want.Interval || got.MaxNodes != want.MaxNodes || got.ThresholdPct != want.ThresholdPct {
		t.Fatalf("round-trip scalars: got %+v want %+v", got, want)
	}
	if len(got.Regions) != len(want.Regions) {
		t.Fatalf("regions len mismatch")
	}
	for i := range got.Regions {
		if got.Regions[i] != want.Regions[i] {
			t.Fatalf("regions[%d] = %q want %q", i, got.Regions[i], want.Regions[i])
		}
	}
	// File landed where expected.
	if _, err := os.Stat(filepath.Join(dir, runtimeDir, settingsSubdir, checkhostSettingsFile)); err != nil {
		t.Fatalf("settings file missing: %v", err)
	}
}

func TestStatusIsFailure(t *testing.T) {
	cases := []struct {
		in   string
		fail bool
	}{
		{"ok", false},
		{"OK", false},
		{"timeout", true},
		{"refused", true},
		{"error", true},
		{"blocked-inferred", true},
		{"", true}, // empty counts as failure
	}
	for _, tc := range cases {
		if got := statusIsFailure(tc.in); got != tc.fail {
			t.Errorf("statusIsFailure(%q) = %v, want %v", tc.in, got, tc.fail)
		}
	}
}

func TestMirrors_UpdateHealth_PreservesTargetTenants(t *testing.T) {
	// UpdateHealth should not clobber operator-managed fields like
	// TargetTenants and Weight.
	r, _ := mustMirrors(t)
	ctx := context.Background()
	m := sampleMirror("keep.example.com")
	m.TargetTenants = []string{"alpha.tld", "beta.tld"}
	m.Weight = 7
	if err := r.Upsert(ctx, m); err != nil {
		t.Fatal(err)
	}
	results := map[string]RegionStatus{
		"x": {Status: "ok"},
	}
	if err := r.UpdateHealth(ctx, "keep.example.com", results, 0.5); err != nil {
		t.Fatal(err)
	}
	got, _ := r.Get("keep.example.com")
	if got.Weight != 7 {
		t.Fatalf("Weight = %d, want 7", got.Weight)
	}
	if len(got.TargetTenants) != 2 || got.TargetTenants[0] != "alpha.tld" {
		t.Fatalf("TargetTenants dropped: %+v", got.TargetTenants)
	}
}
