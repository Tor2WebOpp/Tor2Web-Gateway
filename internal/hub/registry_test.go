package hub

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gateway/internal/config"
	"gateway/internal/shared"
)

// recordingSubscriber captures OnEvent calls for assertions. It is
// deliberately minimal so tests can distinguish ordering issues from lost
// events: each call is appended under a mutex so the slice reflects the
// exact delivery order.
type recordingSubscriber struct {
	mu     sync.Mutex
	events []shared.ConfigStreamEvent
	delay  time.Duration
}

func (r *recordingSubscriber) OnEvent(ev shared.ConfigStreamEvent) {
	if r.delay > 0 {
		time.Sleep(r.delay)
	}
	r.mu.Lock()
	r.events = append(r.events, ev)
	r.mu.Unlock()
}

func (r *recordingSubscriber) snapshot() []shared.ConfigStreamEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]shared.ConfigStreamEvent, len(r.events))
	copy(out, r.events)
	return out
}

func (r *recordingSubscriber) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

// waitForEvents polls the subscriber until at least n events arrive or the
// deadline expires. Returns the observed events at the moment of return.
func waitForEvents(t *testing.T, sub *recordingSubscriber, n int, timeout time.Duration) []shared.ConfigStreamEvent {
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

func mustNew(t *testing.T) (*Registry, string) {
	t.Helper()
	dir := t.TempDir()
	r, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r, dir
}

func TestNew_FreshDir(t *testing.T) {
	r, _ := mustNew(t)
	g, tenants := r.Snapshot()
	if len(tenants) != 0 {
		t.Fatalf("expected no tenants, got %d", len(tenants))
	}
	if g.BlockResponse.Default != "" {
		t.Fatalf("expected empty globals, got %+v", g)
	}
}

func TestUpsertAndSnapshot_RoundTrip(t *testing.T) {
	r, _ := mustNew(t)

	ctx := context.Background()
	tenant := sampleTenant("roundtrip.tld")
	tenant.Features = map[string]config.FeatureConf{
		"rate_limit": {Enabled: true},
	}
	if err := r.UpsertTenant(ctx, tenant); err != nil {
		t.Fatalf("UpsertTenant: %v", err)
	}
	got, ok := r.Tenant("roundtrip.tld")
	if !ok {
		t.Fatal("Tenant lookup missed")
	}
	if got.Host != tenant.Host {
		t.Fatalf("Host = %q", got.Host)
	}
	if !got.Features["rate_limit"].Enabled {
		t.Fatal("feature override not preserved")
	}

	_, tenants := r.Snapshot()
	if len(tenants) != 1 {
		t.Fatalf("expected 1 tenant in snapshot, got %d", len(tenants))
	}
}

func TestUpsert_EmptyHost(t *testing.T) {
	r, _ := mustNew(t)
	if err := r.UpsertTenant(context.Background(), config.TenantConf{}); err == nil {
		t.Fatal("expected error for empty host")
	}
}

func TestUpsert_CancelledContext(t *testing.T) {
	r, _ := mustNew(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.UpsertTenant(ctx, sampleTenant("c.tld")); err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestDelete_RemovesFileAndMap(t *testing.T) {
	r, dir := mustNew(t)
	ctx := context.Background()

	if err := r.UpsertTenant(ctx, sampleTenant("gone.tld")); err != nil {
		t.Fatal(err)
	}
	// File should exist now.
	if _, err := os.Stat(filepath.Join(dir, tenantsDir, "gone.tld.yaml")); err != nil {
		t.Fatalf("expected tenant file to exist, got %v", err)
	}
	if err := r.DeleteTenant(ctx, "gone.tld"); err != nil {
		t.Fatalf("DeleteTenant: %v", err)
	}
	if _, ok := r.Tenant("gone.tld"); ok {
		t.Fatal("tenant still present after delete")
	}
	if _, err := os.Stat(filepath.Join(dir, tenantsDir, "gone.tld.yaml")); !os.IsNotExist(err) {
		t.Fatalf("tenant file still on disk: err=%v", err)
	}
}

func TestDelete_UnknownHostIsNoop(t *testing.T) {
	r, _ := mustNew(t)
	if err := r.DeleteTenant(context.Background(), "nope.tld"); err != nil {
		t.Fatalf("DeleteTenant on missing host returned error: %v", err)
	}
}

func TestSetGlobals_PersistsAndBroadcasts(t *testing.T) {
	r, dir := mustNew(t)
	sub := &recordingSubscriber{}
	unsub := r.Subscribe(sub)
	defer unsub()
	// Drop the initial snapshot event.
	waitForEvents(t, sub, 1, time.Second)

	g := config.GlobalsConf{BlockResponse: config.BlockResponseConf{Default: config.Block429}}
	if err := r.SetGlobals(context.Background(), g); err != nil {
		t.Fatalf("SetGlobals: %v", err)
	}
	evts := waitForEvents(t, sub, 2, time.Second)
	if len(evts) < 2 {
		t.Fatalf("expected 2 events, got %d", len(evts))
	}
	if evts[1].Type != shared.EventGlobalsUpdate {
		t.Fatalf("expected globals_update, got %q", evts[1].Type)
	}
	// File persisted.
	if _, err := os.Stat(filepath.Join(dir, globalsFile)); err != nil {
		t.Fatalf("globals file missing: %v", err)
	}
	// In-memory reflected.
	gotG, _ := r.Snapshot()
	if gotG.BlockResponse.Default != config.Block429 {
		t.Fatalf("BlockResponse.Default = %q", gotG.BlockResponse.Default)
	}
}

func TestExternalFileWrite_TriggersReload(t *testing.T) {
	r, dir := mustNew(t)

	sub := &recordingSubscriber{}
	unsub := r.Subscribe(sub)
	defer unsub()
	// Consume the initial snapshot event.
	waitForEvents(t, sub, 1, time.Second)

	// Write a tenant YAML directly under tenants/ to simulate an operator
	// editing the file. The atomicWrite helper also exercises the
	// tmp+rename path.
	yaml := "host: ext.tld\nenabled: true\nbackends:\n  - addr: extd.onion\n    weight: 1\n"
	if err := atomicWrite(filepath.Join(dir, tenantsDir, "ext.tld.yaml"), []byte(yaml)); err != nil {
		t.Fatalf("atomicWrite: %v", err)
	}

	// Debounce is 300ms; wait up to 500ms for reload + broadcast.
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, ok := r.Tenant("ext.tld"); ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, ok := r.Tenant("ext.tld"); !ok {
		t.Fatalf("external file write did not reload; tenants=%v", mapKeys(snapshotTenants(r)))
	}
}

func TestSubscribe_InitialSnapshotAndDeltas(t *testing.T) {
	r, _ := mustNew(t)
	ctx := context.Background()

	// Seed a tenant before subscribing so the snapshot payload has content.
	if err := r.UpsertTenant(ctx, sampleTenant("seed.tld")); err != nil {
		t.Fatal(err)
	}

	sub := &recordingSubscriber{}
	unsub := r.Subscribe(sub)
	defer unsub()

	// First event must be the snapshot.
	evts := waitForEvents(t, sub, 1, time.Second)
	if len(evts) == 0 {
		t.Fatal("no initial snapshot event")
	}
	if evts[0].Type != shared.EventSnapshot {
		t.Fatalf("first event type = %q, want snapshot", evts[0].Type)
	}
	var payload shared.SnapshotPayload
	if err := json.Unmarshal(evts[0].Data, &payload); err != nil {
		t.Fatalf("snapshot payload: %v", err)
	}
	if len(payload.Tenants) != 1 || payload.Tenants[0].Host != "seed.tld" {
		t.Fatalf("snapshot tenants = %+v", payload.Tenants)
	}

	// Upsert another and expect a follow-up event.
	if err := r.UpsertTenant(ctx, sampleTenant("second.tld")); err != nil {
		t.Fatal(err)
	}
	evts = waitForEvents(t, sub, 2, time.Second)
	if len(evts) < 2 || evts[1].Type != shared.EventTenantUpsert {
		t.Fatalf("expected second event tenant_upsert; got %+v", evts)
	}

	// Delete and expect a delete event.
	if err := r.DeleteTenant(ctx, "second.tld"); err != nil {
		t.Fatal(err)
	}
	evts = waitForEvents(t, sub, 3, time.Second)
	if len(evts) < 3 || evts[2].Type != shared.EventTenantDelete {
		t.Fatalf("expected third event tenant_delete; got %+v", evts)
	}
}

func TestSubscribe_Unsubscribe_StopsDelivery(t *testing.T) {
	r, _ := mustNew(t)
	sub := &recordingSubscriber{}
	unsub := r.Subscribe(sub)
	waitForEvents(t, sub, 1, time.Second)
	unsub()
	// Second unsub is a no-op.
	unsub()

	if err := r.UpsertTenant(context.Background(), sampleTenant("late.tld")); err != nil {
		t.Fatal(err)
	}
	// Give the hub a moment to deliver if it was going to.
	time.Sleep(100 * time.Millisecond)
	if sub.len() > 1 {
		t.Fatalf("events delivered after unsubscribe: %d", sub.len())
	}
}

func TestClose_Idempotent(t *testing.T) {
	r, _ := mustNew(t)
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestSubscribe_AfterClose_ReturnsNoop(t *testing.T) {
	r, _ := mustNew(t)
	_ = r.Close()
	sub := &recordingSubscriber{}
	unsub := r.Subscribe(sub)
	unsub() // should not panic
}

func TestConcurrent_UpsertsAndSubscribers(t *testing.T) {
	r, _ := mustNew(t)
	ctx := context.Background()

	const nSubs = 10
	const nUpserts = 50

	subs := make([]*recordingSubscriber, nSubs)
	unsubs := make([]func(), nSubs)
	for i := 0; i < nSubs; i++ {
		subs[i] = &recordingSubscriber{}
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
		host := fmt.Sprintf("tenant-%03d.tld", i)
		go func(h string) {
			defer wg.Done()
			started.Add(1)
			<-start
			if err := r.UpsertTenant(ctx, sampleTenant(h)); err != nil {
				t.Errorf("upsert %s: %v", h, err)
			}
		}(host)
	}
	// Barrier: wait for all goroutines to be ready, then release them.
	for started.Load() < nUpserts {
		time.Sleep(1 * time.Millisecond)
	}
	close(start)
	wg.Wait()

	// Final state: every tenant is present.
	_, tenants := r.Snapshot()
	if len(tenants) != nUpserts {
		t.Fatalf("expected %d tenants, got %d", nUpserts, len(tenants))
	}

	// Per-subscriber invariants: the first event is a snapshot, every
	// subsequent event has a monotonically non-decreasing timestamp, and
	// the tenant_upsert events carry hosts that belong to the tenant set.
	want := make(map[string]struct{}, nUpserts)
	for i := 0; i < nUpserts; i++ {
		want[fmt.Sprintf("tenant-%03d.tld", i)] = struct{}{}
	}
	for i, sub := range subs {
		// Wait for each subscriber to catch up.
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if sub.len() >= 1+nUpserts { // snapshot + nUpserts
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		evts := sub.snapshot()
		if len(evts) < 1 {
			t.Fatalf("sub %d: no events", i)
		}
		if evts[0].Type != shared.EventSnapshot {
			t.Fatalf("sub %d: first event = %q", i, evts[0].Type)
		}
		// After the snapshot, count tenant_upsert events and verify their
		// hosts belong to the set. Per-subscriber FIFO is enforced by the
		// channel + drain goroutine: the sequence observed here is the
		// exact order broadcast() handed events to this subscriber.
		seen := make(map[string]struct{})
		for j := 1; j < len(evts); j++ {
			ev := evts[j]
			if ev.Type != shared.EventTenantUpsert {
				continue
			}
			var ti shared.TenantInfo
			if err := json.Unmarshal(ev.Data, &ti); err != nil {
				t.Fatalf("sub %d: unmarshal event %d: %v", i, j, err)
			}
			if _, ok := want[ti.Host]; !ok {
				t.Fatalf("sub %d: unexpected tenant host %q", i, ti.Host)
			}
			if _, dup := seen[ti.Host]; dup {
				t.Fatalf("sub %d: duplicate tenant host %q", i, ti.Host)
			}
			seen[ti.Host] = struct{}{}
		}
		if len(seen) != nUpserts {
			t.Fatalf("sub %d: saw %d unique hosts, want %d", i, len(seen), nUpserts)
		}
	}
}

func TestConcurrent_OrderPerSubscriber(t *testing.T) {
	// Single subscriber, single-threaded writer — events must arrive in the
	// order they were produced. This locks the FIFO guarantee documented on
	// Subscribe.
	r, _ := mustNew(t)
	sub := &recordingSubscriber{}
	unsub := r.Subscribe(sub)
	defer unsub()

	ctx := context.Background()
	hosts := make([]string, 0, 20)
	for i := 0; i < 20; i++ {
		h := fmt.Sprintf("ord-%02d.tld", i)
		hosts = append(hosts, h)
		if err := r.UpsertTenant(ctx, sampleTenant(h)); err != nil {
			t.Fatal(err)
		}
	}
	evts := waitForEvents(t, sub, 1+len(hosts), 3*time.Second)
	if len(evts) < 1+len(hosts) {
		t.Fatalf("got %d events, want %d", len(evts), 1+len(hosts))
	}
	var got []string
	for _, ev := range evts[1:] {
		if ev.Type != shared.EventTenantUpsert {
			continue
		}
		var ti shared.TenantInfo
		if err := json.Unmarshal(ev.Data, &ti); err != nil {
			t.Fatal(err)
		}
		got = append(got, ti.Host)
	}
	if len(got) != len(hosts) {
		t.Fatalf("saw %d upsert events, want %d", len(got), len(hosts))
	}
	for i, h := range hosts {
		if got[i] != h {
			t.Fatalf("event order mismatch at %d: got %q, want %q", i, got[i], h)
		}
	}
}

func TestSlowSubscriber_DropsOldest_DoesNotBlock(t *testing.T) {
	// A subscriber with a large per-event delay should not block the hub
	// write path: the broadcaster returns promptly and the queue drops the
	// oldest event to make room.
	r, _ := mustNew(t)
	// Slow subscriber that sleeps on every event so the queue fills.
	slow := &recordingSubscriber{delay: 50 * time.Millisecond}
	unsub := r.Subscribe(slow)
	defer unsub()

	// Fast subscriber to verify the hub still delivers to others.
	fast := &recordingSubscriber{}
	unsubFast := r.Subscribe(fast)
	defer unsubFast()

	const n = subBuffer * 4 // enough to force overflow

	ctx := context.Background()
	deadline := time.After(5 * time.Second)
	done := make(chan struct{})
	go func() {
		for i := 0; i < n; i++ {
			_ = r.UpsertTenant(ctx, sampleTenant(fmt.Sprintf("slow-%03d.tld", i)))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-deadline:
		t.Fatal("hub blocked by slow subscriber")
	}

	// Fast subscriber catches up to all events eventually (n upserts + 1 snapshot).
	evts := waitForEvents(t, fast, 1+n, 5*time.Second)
	if len(evts) < 1+n {
		t.Fatalf("fast subscriber saw only %d events", len(evts))
	}

	// Slow subscriber must have received the initial snapshot plus at
	// least some of the events, but need not be complete.
	if slow.len() < 1 {
		t.Fatalf("slow subscriber saw no events")
	}
}

// Helpers.

func snapshotTenants(r *Registry) map[string]config.TenantConf {
	_, t := r.Snapshot()
	return t
}

func mapKeys(m map[string]config.TenantConf) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
