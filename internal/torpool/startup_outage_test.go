package torpool

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"gateway/internal/config"
)

// Outage-fix regression coverage for Manager.Start — see the 9-hour production
// outage postmortem.
//
//   - 1.2 partial-failure tolerance (Start no longer fails all-or-nothing)
//   - 1.3 parallel spawn (10 instances must not take 10 * bootstrap-timeout)
//   - 1.3 ctx cancellation (SIGTERM during boot must not leak TorInstance)

// newStartTestManager builds a Manager with MinInstances=n and a stubbed
// startSpawner so we never need the real tor binary. We set Tor.Binary to
// something that exec.LookPath can resolve (go itself; tests have it on
// PATH via TestMain) just to clear the early binary check.
func newStartTestManager(t *testing.T, n int, spawner func(ctx context.Context, port int, backend string) (*TorInstance, error)) *Manager {
	t.Helper()
	cfg := &config.Config{}
	cfg.Tor.Binary = fakeTorBin // from regression_test.go TestMain; guaranteed to exist
	cfg.Tor.DataDir = t.TempDir()
	cfg.Tor.SocksBasePort = 30000 + int(time.Now().UnixNano()%10000)
	cfg.Tor.MinInstances = n
	cfg.Tor.MaxInstances = n * 2
	cfg.Tor.BootstrapTimeout = 5 * time.Second
	cfg.Pool.ScaleUpThreshold = 0.8
	cfg.Pool.ScaleDownThreshold = 0.2
	mgr := NewManager(cfg)
	mgr.startSpawner = spawner
	return mgr
}

// TestOutage1_2_StartTolerantPartial asserts that with a fake spawner where
// 7 of 10 succeed, Start returns nil and the pool ends up with 7 instances.
// Pre-fix: a single error aborted Start and systemd restart-looped forever.
func TestOutage1_2_StartTolerantPartial(t *testing.T) {
	var attempts atomic.Int64
	spawner := func(ctx context.Context, port int, backend string) (*TorInstance, error) {
		n := attempts.Add(1)
		// Fail 3 of 10, succeed on the rest. We deterministically pick the
		// indexes 2, 4, 6 (ports base+2, base+4, base+6) to simulate a
		// patchy bootstrap without relying on goroutine scheduling.
		if n == 2 || n == 4 || n == 6 {
			return nil, errors.New("synthetic bootstrap failure")
		}
		inst := &TorInstance{Port: port, Backend: backend, exited: make(chan struct{})}
		inst.Alive.Store(true)
		return inst, nil
	}

	mgr := newStartTestManager(t, 10, spawner)
	defer mgr.Shutdown()

	if err := mgr.Start(context.Background()); err != nil {
		t.Fatalf("Start() with 7/10 success returned err=%v; want nil (tolerant)", err)
	}
	total, alive := mgr.Count()
	if total != 7 {
		t.Fatalf("pool size = %d, want 7 after tolerant Start", total)
	}
	if alive != 7 {
		t.Fatalf("alive count = %d, want 7", alive)
	}

	// Instances must be in deterministic port order so balancer/hash paths
	// downstream see a stable layout.
	insts := mgr.Instances()
	for i := 1; i < len(insts); i++ {
		if insts[i-1].Port >= insts[i].Port {
			t.Fatalf("instances not port-sorted: %d >= %d", insts[i-1].Port, insts[i].Port)
		}
	}
}

// TestOutage1_2_StartZeroSuccessAggregates asserts that when no instance
// comes up, Start returns an error that mentions counts AND the individual
// spawn failures (errors.Join wrapped). This gives operators something to
// grep for in journald instead of "unknown failure".
func TestOutage1_2_StartZeroSuccessAggregates(t *testing.T) {
	spawner := func(ctx context.Context, port int, backend string) (*TorInstance, error) {
		return nil, fmt.Errorf("boom on %d", port)
	}
	mgr := newStartTestManager(t, 4, spawner)
	defer mgr.Shutdown()

	err := mgr.Start(context.Background())
	if err == nil {
		t.Fatalf("Start() with 0/4 success returned nil, want aggregated err")
	}
	// Count appears in the error so operators see the ratio.
	if !contains(err.Error(), "0 of 4") {
		t.Errorf("err %q missing count summary '0 of 4'", err.Error())
	}
	// At least one per-port failure is wrapped.
	if !contains(err.Error(), "boom on") {
		t.Errorf("err %q missing per-port detail", err.Error())
	}
	// Pool must be empty — we don't want to leak the processes that did
	// come up in the minority of runs.
	total, _ := mgr.Count()
	if total != 0 {
		t.Fatalf("pool size after failed Start = %d, want 0", total)
	}
}

// TestOutage1_2_StartRespectsMinSuccessfulOnStart asserts the new config
// knob is honoured: require 8 of 10, deliver only 6, expect failure.
func TestOutage1_2_StartRespectsMinSuccessfulOnStart(t *testing.T) {
	var attempts atomic.Int64
	spawner := func(ctx context.Context, port int, backend string) (*TorInstance, error) {
		n := attempts.Add(1)
		if n > 6 {
			return nil, errors.New("synthetic")
		}
		// Pre-close exited so Start's cleanup-killAndWait returns instantly
		// instead of eating the 5s waitInstanceExit timeout per instance.
		exited := make(chan struct{})
		close(exited)
		inst := &TorInstance{Port: port, Backend: backend, exited: exited}
		inst.Alive.Store(true)
		return inst, nil
	}
	mgr := newStartTestManager(t, 10, spawner)
	mgr.cfg.Tor.MinSuccessfulOnStart = 8
	defer mgr.Shutdown()

	err := mgr.Start(context.Background())
	if err == nil {
		t.Fatal("Start() with 6 <8 successes returned nil, want err")
	}
}

// TestOutage1_3_StartParallel asserts that 10 instances each taking 200ms
// complete in well under 10*200ms (sequential would be 2s). Budget: 600ms.
func TestOutage1_3_StartParallel(t *testing.T) {
	spawner := func(ctx context.Context, port int, backend string) (*TorInstance, error) {
		// Each spawner sleeps 200ms to simulate tor bootstrap. If Start is
		// parallel, wall-clock is ~200ms + scheduling overhead. If sequential,
		// wall-clock is ~2s.
		select {
		case <-time.After(200 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		inst := &TorInstance{Port: port, Backend: backend, exited: make(chan struct{})}
		inst.Alive.Store(true)
		return inst, nil
	}
	mgr := newStartTestManager(t, 10, spawner)
	defer mgr.Shutdown()

	start := time.Now()
	if err := mgr.Start(context.Background()); err != nil {
		t.Fatalf("Start() err=%v", err)
	}
	elapsed := time.Since(start)
	if elapsed >= 600*time.Millisecond {
		t.Fatalf("Start() took %v for 10x200ms spawners; parallelism broken (sequential budget would be ~2s)", elapsed)
	}
	if total, _ := mgr.Count(); total != 10 {
		t.Fatalf("pool size = %d, want 10", total)
	}
}

// TestOutage1_3_StartCtxCancelMidSpawn asserts that cancelling ctx during a
// parallel spawn returns ctx.Err() and leaves the pool empty (no half-started
// entries leak into m.instances).
func TestOutage1_3_StartCtxCancelMidSpawn(t *testing.T) {
	release := make(chan struct{})
	var spawned atomic.Int64
	spawner := func(ctx context.Context, port int, backend string) (*TorInstance, error) {
		spawned.Add(1)
		// Block until released OR ctx cancelled.
		select {
		case <-release:
			exited := make(chan struct{})
			close(exited)
			inst := &TorInstance{Port: port, Backend: backend, exited: exited}
			inst.Alive.Store(true)
			return inst, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	mgr := newStartTestManager(t, 5, spawner)
	defer mgr.Shutdown()

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Start(ctx)
	}()

	// Give goroutines time to enter spawner.
	deadline := time.Now().Add(2 * time.Second)
	for spawned.Load() < 5 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if spawned.Load() < 5 {
		t.Fatalf("only %d/5 spawners reached block — parallelism broken", spawned.Load())
	}

	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Start() returned err=%v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start() did not return within 5s of ctx cancel")
	}

	// Unblock any stragglers so goroutines exit. (They already saw ctx
	// cancel, but closing release is still safe.)
	close(release)

	// No partial entries in the pool.
	if total, _ := mgr.Count(); total != 0 {
		t.Fatalf("pool size after cancelled Start = %d, want 0 (no leak)", total)
	}
}

// contains is a tiny helper to avoid pulling in strings in this test file.
func contains(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
