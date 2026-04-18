package negcache

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock is a minimal monotonic, mutable clock for tests.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(t time.Time) *fakeClock {
	return &fakeClock{now: t}
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

func newCache(t *testing.T, ttl time.Duration, threshold int) (*Cache, *fakeClock) {
	t.Helper()
	c := NewCache(ttl, threshold)
	fc := newFakeClock(time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC))
	c.SetClock(fc.Now)
	return c, fc
}

func TestRecordFailureBelowThresholdNotBlacklisted(t *testing.T) {
	c, _ := newCache(t, 5*time.Minute, 5)

	for i := 0; i < 4; i++ {
		c.RecordFailure("tenant-a", "onion-a")
	}
	if c.IsBlacklisted("tenant-a", "onion-a") {
		t.Fatalf("expected not blacklisted after 4/5 failures")
	}
	if got := len(c.Snapshot()); got != 0 {
		t.Fatalf("expected empty snapshot, got %d entries", got)
	}
}

func TestRecordFailureAtThresholdBlacklisted(t *testing.T) {
	c, fc := newCache(t, 5*time.Minute, 3)

	for i := 0; i < 3; i++ {
		c.RecordFailure("tenant-a", "onion-a")
	}
	if !c.IsBlacklisted("tenant-a", "onion-a") {
		t.Fatalf("expected blacklisted after reaching threshold")
	}

	snap := c.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("expected 1 snapshot entry, got %d", len(snap))
	}
	if snap[0].Tenant != "tenant-a" || snap[0].Onion != "onion-a" {
		t.Fatalf("unexpected snapshot entry: %+v", snap[0])
	}
	expected := fc.Now().Add(5 * time.Minute)
	if !snap[0].ExpiresAt.Equal(expected) {
		t.Fatalf("expected ExpiresAt %v, got %v", expected, snap[0].ExpiresAt)
	}
}

func TestIsBlacklistedFalseAfterTTL(t *testing.T) {
	c, fc := newCache(t, 1*time.Minute, 2)

	c.RecordFailure("t", "o")
	c.RecordFailure("t", "o")
	if !c.IsBlacklisted("t", "o") {
		t.Fatalf("expected blacklisted immediately after threshold")
	}

	// Just before expiry, still blacklisted.
	fc.Advance(59 * time.Second)
	if !c.IsBlacklisted("t", "o") {
		t.Fatalf("expected still blacklisted 59s in")
	}

	// Past expiry, no longer blacklisted.
	fc.Advance(2 * time.Second)
	if c.IsBlacklisted("t", "o") {
		t.Fatalf("expected not blacklisted after TTL")
	}
}

func TestRecordSuccessResetsCounter(t *testing.T) {
	c, _ := newCache(t, 5*time.Minute, 3)

	c.RecordFailure("t", "o")
	c.RecordFailure("t", "o")
	c.RecordSuccess("t", "o")

	// After reset, two more failures should not trip the threshold.
	c.RecordFailure("t", "o")
	c.RecordFailure("t", "o")
	if c.IsBlacklisted("t", "o") {
		t.Fatalf("expected not blacklisted: counter should have been reset")
	}

	// A third failure after reset pushes past the threshold again.
	c.RecordFailure("t", "o")
	if !c.IsBlacklisted("t", "o") {
		t.Fatalf("expected blacklisted after 3 failures post-reset")
	}
}

func TestRecordSuccessRemovesBlacklistEntry(t *testing.T) {
	c, _ := newCache(t, 5*time.Minute, 2)

	c.RecordFailure("t", "o")
	c.RecordFailure("t", "o")
	if !c.IsBlacklisted("t", "o") {
		t.Fatalf("expected blacklisted pre-success")
	}

	c.RecordSuccess("t", "o")
	if c.IsBlacklisted("t", "o") {
		t.Fatalf("expected RecordSuccess to remove blacklist entry")
	}
}

func TestSweepRemovesExpired(t *testing.T) {
	c, fc := newCache(t, 1*time.Minute, 2)

	// Insert two entries at t=0.
	c.RecordFailure("t", "a")
	c.RecordFailure("t", "a")
	c.RecordFailure("t", "b")
	c.RecordFailure("t", "b")

	// Advance into the middle of their lifetime, then insert one that
	// will survive the sweep.
	fc.Advance(30 * time.Second)
	c.RecordFailure("t", "c")
	c.RecordFailure("t", "c")

	// Push past the first two entries' expiry but not the third's.
	fc.Advance(45 * time.Second) // first two expired at 60s (now 75s)

	removed := c.Sweep()
	if removed != 2 {
		t.Fatalf("expected Sweep to remove 2 entries, removed %d", removed)
	}

	if c.IsBlacklisted("t", "a") || c.IsBlacklisted("t", "b") {
		t.Fatalf("expected expired entries to be gone after Sweep")
	}
	if !c.IsBlacklisted("t", "c") {
		t.Fatalf("expected unexpired entry to remain after Sweep")
	}

	// A follow-up sweep with nothing to remove must report zero.
	if got := c.Sweep(); got != 0 {
		t.Fatalf("expected second Sweep to remove 0, got %d", got)
	}
}

func TestSnapshotLiveState(t *testing.T) {
	c, fc := newCache(t, 5*time.Minute, 2)

	c.RecordFailure("alpha", "x")
	c.RecordFailure("alpha", "x")
	c.RecordFailure("beta", "y")
	c.RecordFailure("beta", "y")
	c.RecordFailure("alpha", "z") // only one failure, not blacklisted

	snap := c.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("expected 2 entries in snapshot, got %d", len(snap))
	}

	// Snapshot is sorted by (tenant, onion).
	if snap[0].Tenant != "alpha" || snap[0].Onion != "x" {
		t.Fatalf("unexpected snap[0]: %+v", snap[0])
	}
	if snap[1].Tenant != "beta" || snap[1].Onion != "y" {
		t.Fatalf("unexpected snap[1]: %+v", snap[1])
	}

	// Entries that expire disappear from the snapshot even without Sweep.
	fc.Advance(6 * time.Minute)
	if got := len(c.Snapshot()); got != 0 {
		t.Fatalf("expected empty snapshot post-expiry, got %d", got)
	}
}

func TestConfigureHotReload(t *testing.T) {
	c, fc := newCache(t, 5*time.Minute, 5)

	// With threshold=5, 4 failures are not enough.
	for i := 0; i < 4; i++ {
		c.RecordFailure("t", "o")
	}
	if c.IsBlacklisted("t", "o") {
		t.Fatalf("unexpected blacklist with threshold=5 and 4 failures")
	}

	// Tighten the threshold; the next failure should trip the blacklist.
	c.Configure(10*time.Minute, 5)
	c.RecordFailure("t", "o")
	if !c.IsBlacklisted("t", "o") {
		t.Fatalf("expected blacklist with threshold=5 and 5 failures")
	}

	// New entries use the new TTL.
	c.RecordSuccess("t", "o") // reset for next test pair
	c.Configure(2*time.Minute, 2)
	c.RecordFailure("t", "o2")
	c.RecordFailure("t", "o2")
	snap := c.Snapshot()
	var found *Entry
	for i := range snap {
		if snap[i].Onion == "o2" {
			found = &snap[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected o2 in snapshot")
	}
	if want := fc.Now().Add(2 * time.Minute); !found.ExpiresAt.Equal(want) {
		t.Fatalf("expected ExpiresAt %v, got %v", want, found.ExpiresAt)
	}
}

func TestConfigureZeroThresholdDisables(t *testing.T) {
	c, _ := newCache(t, 5*time.Minute, 0)

	for i := 0; i < 100; i++ {
		c.RecordFailure("t", "o")
	}
	if c.IsBlacklisted("t", "o") {
		t.Fatalf("expected threshold=0 to never blacklist")
	}
}

func TestConfigureZeroTTLNoInsertion(t *testing.T) {
	c, _ := newCache(t, 0, 2)

	c.RecordFailure("t", "o")
	c.RecordFailure("t", "o")
	if c.IsBlacklisted("t", "o") {
		t.Fatalf("expected ttl=0 to suppress blacklist insertion")
	}
}

func TestIsBlacklistedEagerExpiryCleanup(t *testing.T) {
	c, fc := newCache(t, 1*time.Minute, 2)

	c.RecordFailure("t", "o")
	c.RecordFailure("t", "o")
	fc.Advance(2 * time.Minute)

	// IsBlacklisted should return false AND drop the expired entry.
	if c.IsBlacklisted("t", "o") {
		t.Fatalf("expected expired entry to read false")
	}
	if got := len(c.Snapshot()); got != 0 {
		t.Fatalf("expected eager cleanup: snapshot should be empty, got %d", got)
	}
}

func TestConcurrentRecordFailure(t *testing.T) {
	c, _ := newCache(t, 5*time.Minute, 10)

	const (
		tenants    = 10
		onions     = 10
		goroutines = 100
		perRoutine = 5
	)

	// Seed counters so race detector exercises both Load and LoadOrStore paths.
	var wg sync.WaitGroup
	var failures atomic.Int64
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perRoutine; i++ {
				tenantIdx := (g + i) % tenants
				onionIdx := (g * 3 + i*7) % onions
				tenant := string(rune('A' + tenantIdx))
				onion := string(rune('a' + onionIdx))
				c.RecordFailure(tenant, onion)
				failures.Add(1)
				// Interleave the other operations so the race detector sees
				// each sync.Map branch plus the config RWMutex under load.
				if i%2 == 0 {
					_ = c.IsBlacklisted(tenant, onion)
				}
				if i%3 == 0 {
					_ = c.Snapshot()
				}
			}
		}(g)
	}
	wg.Wait()

	if failures.Load() != int64(goroutines*perRoutine) {
		t.Fatalf("unexpected failure count: %d", failures.Load())
	}

	// Final sweep should not panic and must return a non-negative count.
	if got := c.Sweep(); got < 0 {
		t.Fatalf("Sweep returned negative: %d", got)
	}
}

func TestConcurrentConfigureAndRecord(t *testing.T) {
	c, _ := newCache(t, 1*time.Minute, 3)

	done := make(chan struct{})
	var wg sync.WaitGroup

	// Reconfigure in a loop.
	wg.Add(1)
	go func() {
		defer wg.Done()
		toggle := false
		for {
			select {
			case <-done:
				return
			default:
			}
			if toggle {
				c.Configure(2*time.Minute, 2)
			} else {
				c.Configure(1*time.Minute, 5)
			}
			toggle = !toggle
		}
	}()

	// Hammer RecordFailure / RecordSuccess.
	for g := 0; g < 50; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				tenant := string(rune('A' + (g % 5)))
				onion := string(rune('a' + (i % 5)))
				if i%10 == 0 {
					c.RecordSuccess(tenant, onion)
				} else {
					c.RecordFailure(tenant, onion)
				}
			}
		}(g)
	}

	// Also run snapshot+sweep concurrently.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = c.Snapshot()
			_ = c.Sweep()
		}
	}()

	// Let the writers and the reconfigurer settle.
	wgDone := make(chan struct{})
	go func() {
		// Stop the reconfigurer after the mutating goroutines finish.
		// This goroutine synchronises only on wgDone.
		<-wgDone
		close(done)
	}()

	// Wait for all RecordFailure/Success/snapshot/sweep goroutines.
	// Signal 'done' by closing wgDone after the record loop group.
	goWait := make(chan struct{})
	go func() {
		wg.Wait()
		close(goWait)
	}()

	// Close wgDone as soon as the 50 + 1 (snapshot/sweep) groups exit.
	// The reconfigurer is the only remaining goroutine at that point.
	// Here we deliberately order: close wgDone first, then wait for all.
	// To keep the logic simple: close wgDone unconditionally and let
	// wg.Wait() report when everything (including the reconfigurer) has
	// stopped.
	close(wgDone)
	<-goWait
}
