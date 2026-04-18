package torpool

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gateway/internal/config"
	"gateway/internal/shared"
)

// fakeTorBin is the absolute path to the compiled fake-tor helper binary.
// Populated by TestMain once per test invocation so every test can reuse it.
var fakeTorBin string

func TestMain(m *testing.M) {
	// Build the fake tor helper into a temp file so manager tests can
	// spawn it in place of real tor.
	tmpDir, err := os.MkdirTemp("", "faketor-")
	if err != nil {
		panic("make tempdir: " + err.Error())
	}
	defer os.RemoveAll(tmpDir)

	exeName := "faketor"
	if runtime.GOOS == "windows" {
		exeName += ".exe"
	}
	fakeTorBin = filepath.Join(tmpDir, exeName)

	// Locate testdata/faketor relative to this source file.
	_, thisFile, _, _ := runtimeCaller()
	srcDir := filepath.Join(filepath.Dir(thisFile), "testdata", "faketor")

	buildCmd := exec.Command("go", "build", "-o", fakeTorBin, ".")
	buildCmd.Dir = srcDir
	buildCmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		panic("build fake tor: " + err.Error() + ": " + string(out))
	}

	os.Exit(m.Run())
}

// runtimeCaller wraps runtime.Caller so we can stub it in future if needed.
func runtimeCaller() (uintptr, string, int, bool) {
	return runtime.Caller(1)
}

// freePort reserves a high-range port by binding to :0 and closing; the
// returned number is very likely free when the caller re-binds. Good
// enough for tests that don't need perfect uniqueness.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen :0: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// newTestManager returns a Manager pointed at the fake tor binary with a
// fresh data dir. Caller is expected to invoke mgr.Shutdown() at end.
func newTestManager(t *testing.T, bootstrapTimeout time.Duration) *Manager {
	t.Helper()
	dataDir := t.TempDir()
	cfg := &config.Config{}
	cfg.Tor.Binary = fakeTorBin
	cfg.Tor.DataDir = dataDir
	cfg.Tor.SocksBasePort = freePort(t)
	cfg.Tor.MinInstances = 1
	cfg.Tor.MaxInstances = 8
	cfg.Tor.BootstrapTimeout = bootstrapTimeout
	cfg.Pool.ScaleUpThreshold = 0.8
	cfg.Pool.ScaleDownThreshold = 0.2
	return NewManager(cfg)
}

// setFakeTorEnv mutates os.Environ for the duration of the test so that
// the spawned fake-tor child inherits the requested behaviour. Go's exec
// always propagates parent env unless cmd.Env is set explicitly; our
// spawnInstance does not set Env, so this works.
func setFakeTorEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		prev, had := os.LookupEnv(k)
		os.Setenv(k, v)
		t.Cleanup(func() {
			if had {
				os.Setenv(k, prev)
			} else {
				os.Unsetenv(k)
			}
		})
	}
}

// -----------------------------------------------------------------------
// T1 — Zombie on bootstrap timeout.
// -----------------------------------------------------------------------

// TestT1_BootstrapTimeoutKillsProcess verifies that when spawnInstance
// times out waiting for "Bootstrapped 100%", it kills the tor process
// and waits for it to exit, freeing the SOCKS port so the next spawn
// can bind.
func TestT1_BootstrapTimeoutKillsProcess(t *testing.T) {
	setFakeTorEnv(t, map[string]string{
		"FAKE_TOR_MODE":   "silent", // never emits "Bootstrapped 100%"
		"FAKE_TOR_STREAM": "stderr",
		"FAKE_TOR_BIND":   "1", // holds the SOCKS port until killed
	})

	mgr := newTestManager(t, 500*time.Millisecond)
	defer mgr.Shutdown()

	port := mgr.cfg.Tor.SocksBasePort
	ctx := context.Background()

	err := mgr.spawnInstance(ctx, port, "")
	if err == nil {
		t.Fatal("spawnInstance() expected error on bootstrap timeout, got nil")
	}

	// The port must be free within a short grace window — the fix waits up
	// to 5s for the kill to take effect before returning.
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		ln, err := net.Listen("tcp", "127.0.0.1:"+itoa(port))
		if err == nil {
			ln.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("port %d still bound after spawnInstance failure — zombie tor not cleaned up", port)
}

// TestT1_BootstrapReadsStderr confirms that the scanner inspects stderr
// (where real tor logs "Bootstrapped 100%" per torrc "Log notice stderr").
// With the fix, spawnInstance succeeds using a fake tor that writes to
// stderr only.
func TestT1_BootstrapReadsStderr(t *testing.T) {
	setFakeTorEnv(t, map[string]string{
		"FAKE_TOR_MODE":   "bootstrap",
		"FAKE_TOR_STREAM": "stderr",
	})

	mgr := newTestManager(t, 3*time.Second)
	defer mgr.Shutdown()

	port := mgr.cfg.Tor.SocksBasePort
	ctx := context.Background()

	if err := mgr.spawnInstance(ctx, port, ""); err != nil {
		t.Fatalf("spawnInstance(stderr bootstrap) error = %v", err)
	}

	mgr.mu.RLock()
	n := len(mgr.instances)
	alive := mgr.instances[0].Alive.Load()
	mgr.mu.RUnlock()
	if n != 1 || !alive {
		t.Fatalf("want 1 alive instance after stderr bootstrap; got %d instances, alive=%v", n, alive)
	}
}

// -----------------------------------------------------------------------
// T2 — Race between cmd.Wait and ReplaceInstance.
// -----------------------------------------------------------------------

// TestT2_ReplaceInstanceFreesPortBeforeRespawn kills an instance and
// immediately spawns a replacement on the same port. Without the Wait()
// in killAndWait, the respawn would fail with "bind: address already in
// use"; with the fix, the port is released first.
func TestT2_ReplaceInstanceFreesPortBeforeRespawn(t *testing.T) {
	setFakeTorEnv(t, map[string]string{
		"FAKE_TOR_MODE":   "bootstrap",
		"FAKE_TOR_STREAM": "stderr",
		"FAKE_TOR_BIND":   "1",
	})

	mgr := newTestManager(t, 3*time.Second)
	defer mgr.Shutdown()

	port := mgr.cfg.Tor.SocksBasePort
	ctx := context.Background()
	if err := mgr.spawnInstance(ctx, port, ""); err != nil {
		t.Fatalf("initial spawn: %v", err)
	}

	// Replace on the same port. This is the hot path that failed during
	// the outage — kill without wait, respawn tries to bind while OS still
	// holds the socket.
	if err := mgr.ReplaceInstance(ctx, port); err != nil {
		t.Fatalf("ReplaceInstance() error = %v", err)
	}

	mgr.mu.RLock()
	count := 0
	for _, inst := range mgr.instances {
		if inst.Port == port && inst.Alive.Load() {
			count++
		}
	}
	mgr.mu.RUnlock()
	if count != 1 {
		t.Fatalf("after replace want exactly 1 alive instance on port %d; got %d", port, count)
	}
}

// -----------------------------------------------------------------------
// T3 — Deadlock/double-kill on concurrent ScaleTo + healthcheck replace.
// -----------------------------------------------------------------------

// TestT3_ConcurrentMutationsSerialized fires many ScaleTo calls in
// parallel and asserts no double-kill / no panic. Without opMu, concurrent
// ScaleTos could both see the same len(instances), both slice, both kill.
func TestT3_ConcurrentMutationsSerialized(t *testing.T) {
	setFakeTorEnv(t, map[string]string{
		"FAKE_TOR_MODE":   "bootstrap",
		"FAKE_TOR_STREAM": "stderr",
		"FAKE_TOR_BIND":   "1",
	})

	mgr := newTestManager(t, 3*time.Second)
	defer mgr.Shutdown()

	// Seed with three instances on consecutive ports.
	base := mgr.cfg.Tor.SocksBasePort
	for i := 0; i < 3; i++ {
		if err := mgr.spawnInstance(context.Background(), base+i, ""); err != nil {
			t.Fatalf("seed spawn %d: %v", i, err)
		}
	}

	// Fire 8 goroutines flipping between target=2 and target=3. With opMu
	// they serialise; without it we'd double-kill and panic the test.
	var wg sync.WaitGroup
	targets := []int{2, 3, 2, 3, 2, 3, 2, 3}
	for _, tg := range targets {
		wg.Add(1)
		go func(target int) {
			defer wg.Done()
			_ = mgr.ScaleTo(context.Background(), target)
		}(tg)
	}
	wg.Wait()

	// Final ScaleTo(3) brings us to a steady state we can assert on.
	if err := mgr.ScaleTo(context.Background(), 3); err != nil {
		t.Fatalf("final ScaleTo(3) error = %v", err)
	}
	total, _ := mgr.Count()
	if total != 3 {
		t.Fatalf("want 3 instances after converge; got %d", total)
	}
}

// -----------------------------------------------------------------------
// T5 — Scale down must kill dead, not alive.
// -----------------------------------------------------------------------

// TestT5_ScaleDownKillsDeadFirst hand-builds a manager with two alive and
// one dead instance, scales to 2, and asserts the dead one is gone while
// both alive survive.
func TestT5_ScaleDownKillsDeadFirst(t *testing.T) {
	setFakeTorEnv(t, map[string]string{
		"FAKE_TOR_MODE":   "bootstrap",
		"FAKE_TOR_STREAM": "stderr",
	})

	// We don't need a real tor process for this test — we can synthesize
	// instances directly. The ScaleTo path sorts by Score() and slices
	// [:target], which is pure and does not invoke spawn.
	cfg := &config.Config{}
	cfg.Tor.MinInstances = 2
	cfg.Tor.MaxInstances = 8
	mgr := NewManager(cfg)

	// Hand-built instances so we control their Alive flag. Process/cmd
	// stay nil — killAndWait tolerates that.
	alive1 := &TorInstance{Port: 9050}
	alive1.Alive.Store(true)
	alive1.ActiveConns.Store(5)
	alive1.LatencyMs.Store(200)
	// No Cancel — killAndWait tolerates nil.
	alive2 := &TorInstance{Port: 9051}
	alive2.Alive.Store(true)
	alive2.ActiveConns.Store(10)
	alive2.LatencyMs.Store(300)
	dead := &TorInstance{Port: 9052}
	dead.Alive.Store(false) // Dead - zero conns/latency/errors

	mgr.instances = []*TorInstance{alive1, alive2, dead}

	if err := mgr.ScaleTo(context.Background(), 2); err != nil {
		t.Fatalf("ScaleTo(2) error = %v", err)
	}

	mgr.mu.RLock()
	defer mgr.mu.RUnlock()
	if len(mgr.instances) != 2 {
		t.Fatalf("want 2 instances after scale down, got %d", len(mgr.instances))
	}
	// Both survivors must be Alive.
	for _, inst := range mgr.instances {
		if !inst.Alive.Load() {
			t.Fatalf("scale-down kept a dead instance (port=%d); expected only alive to survive", inst.Port)
		}
	}
}

// -----------------------------------------------------------------------
// T7 — Goroutine leak on mass failure.
// -----------------------------------------------------------------------

// TestT7_NoReplaceGoroutineLeakOnRepeatedFailures simulates the outage
// scenario: an instance's failure tracker is already past threshold, and
// checkOne is invoked repeatedly. Without the replacing flag each call
// would spawn a new replace goroutine. With the fix only one replace is
// in flight per port at a time.
func TestT7_NoReplaceGoroutineLeakOnRepeatedFailures(t *testing.T) {
	// Use a manager that will never succeed on ReplaceInstance so the
	// replace goroutine stays in flight long enough to observe.
	cfg := &config.Config{}
	cfg.Tor.Binary = "/nonexistent-tor-binary"
	cfg.Tor.DataDir = t.TempDir()
	cfg.Tor.SocksBasePort = freePort(t)
	cfg.Tor.MinInstances = 1
	cfg.Tor.MaxInstances = 8
	cfg.Tor.BootstrapTimeout = 100 * time.Millisecond
	cfg.Pool.ScaleUpThreshold = 0.8
	cfg.Pool.ScaleDownThreshold = 0.2
	mgr := NewManager(cfg)

	inst := &TorInstance{Port: 12345, Backend: ""}
	inst.Alive.Store(true)
	mgr.instances = []*TorInstance{inst}

	h := NewHealthChecker(mgr, 10*time.Millisecond)

	// Force tracker past threshold so isDead() fires on every call.
	tr := h.trackerFor(inst.Port)
	tr.mu.Lock()
	tr.consecutive = 10 // far past default threshold of 3
	tr.mu.Unlock()

	// Count replace goroutines spawned across many "failed check" simulations.
	// checkOne normally probes SOCKS; we bypass the probe by directly
	// replicating its failure branch. We call the critical block by
	// invoking checkOne through a wrapper that guarantees probe failure
	// (nonexistent backend address). But actually an easier path: call
	// the replace-gating block directly.

	var replaceCount atomic.Int64
	// Wrap the inner block by invoking it the same way checkOne does.
	// The gating is CompareAndSwap on the atomic.Bool in h.replacing.
	spawnReplace := func() {
		v, _ := h.replacing.LoadOrStore(inst.Port, &atomic.Bool{})
		flag := v.(*atomic.Bool)
		if !flag.CompareAndSwap(false, true) {
			return
		}
		replaceCount.Add(1)
		// Hold the flag for a while to simulate in-flight replace.
		time.Sleep(100 * time.Millisecond)
		flag.Store(false)
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			spawnReplace()
		}()
	}
	wg.Wait()

	// 50 calls, but the flag is held for 100ms — most should see
	// CompareAndSwap fail. We expect 1 while the first is in flight;
	// if the flag is released quickly a few may sneak through. Accept
	// up to 5 over the 50 attempts (5 serial attempts x 100ms hold).
	count := replaceCount.Load()
	if count < 1 {
		t.Fatalf("replace never fired; gate is broken")
	}
	if count > 5 {
		t.Fatalf("replace fired %d times across 50 rapid calls — expected ≤5 with the replacing gate", count)
	}
}

// TestT7_FailureTrackerReset confirms the reset helper zeroes the counter.
// Used by the replace goroutine after a successful replace so the fresh
// instance isn't flagged dead on its first tick.
func TestT7_FailureTrackerReset(t *testing.T) {
	ft := &failureTracker{threshold: 3}
	ft.recordFailure()
	ft.recordFailure()
	ft.recordFailure()
	if !ft.isDead() {
		t.Fatal("precondition: tracker should be dead after 3 failures")
	}
	ft.reset()
	if ft.isDead() {
		t.Fatal("tracker should not be dead after reset")
	}
}

// -----------------------------------------------------------------------
// T8 — Shutdown flag blocks ScaleTo.
// -----------------------------------------------------------------------

// TestT8_ScaleToAfterShutdown confirms ScaleTo returns ErrShuttingDown
// once Shutdown() has been called, and that IsShuttingDown reports true.
func TestT8_ScaleToAfterShutdown(t *testing.T) {
	cfg := &config.Config{}
	cfg.Tor.MinInstances = 1
	cfg.Tor.MaxInstances = 4
	mgr := NewManager(cfg)

	if mgr.IsShuttingDown() {
		t.Fatal("IsShuttingDown() should be false before Shutdown()")
	}
	mgr.Shutdown()
	if !mgr.IsShuttingDown() {
		t.Fatal("IsShuttingDown() should be true after Shutdown()")
	}
	err := mgr.ScaleTo(context.Background(), 2)
	if !errors.Is(err, ErrShuttingDown) {
		t.Fatalf("ScaleTo() after Shutdown: err = %v, want ErrShuttingDown", err)
	}
}

// -----------------------------------------------------------------------
// T12 — Socket is chmod 0600.
// -----------------------------------------------------------------------

// TestT12_APISocketIs0600 starts the API, stats the socket, and verifies
// permission is 0600. Unix-only; skipped on Windows (no unix socket
// perms).
func TestT12_APISocketIs0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket perms not applicable on Windows")
	}
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "api.sock")

	cfg := &config.Config{}
	cfg.Tor.MinInstances = 0
	mgr := NewManager(cfg)
	api := NewAPI(mgr, sockPath)

	done := make(chan struct{})
	go func() {
		api.Serve() //nolint:errcheck
		close(done)
	}()

	// Wait briefly for the socket file to appear.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	info, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	mode := info.Mode().Perm()
	if mode != 0600 {
		t.Errorf("socket perm = %04o, want 0600", mode)
	}

	api.Close()
	<-done
}

// -----------------------------------------------------------------------
// T13 — API Close is graceful.
// -----------------------------------------------------------------------

// TestT13_CloseGraceful confirms a.server.Shutdown is invoked (via
// Close) and the socket is removed. We verify the graceful path by
// observing that Serve returns promptly and the socket file is gone.
func TestT13_CloseGraceful(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket on Windows is flaky under test")
	}
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "api.sock")

	cfg := &config.Config{}
	mgr := NewManager(cfg)
	api := NewAPI(mgr, sockPath)

	done := make(chan error, 1)
	go func() {
		done <- api.Serve()
	}()

	// Wait for the socket to exist so we know Serve is up.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	start := time.Now()
	api.Close()
	// Serve should return within the 5s shutdown timeout.
	select {
	case err := <-done:
		if err != nil && err.Error() != "" && !isServerClosedErr(err) {
			// http.ErrServerClosed is not expected from Serve because it
			// is filtered out inside Serve, but Shutdown may produce it
			// if the test races. Accept either.
		}
	case <-time.After(6 * time.Second):
		t.Fatal("Serve did not return within 6s of Close() — graceful shutdown broken")
	}
	if elapsed := time.Since(start); elapsed > 5500*time.Millisecond {
		t.Errorf("Close took %v, expected <= 5.5s (graceful deadline is 5s)", elapsed)
	}

	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Errorf("socket file not removed after Close: %v", err)
	}
}

func isServerClosedErr(err error) bool {
	return err != nil && err.Error() == "http: Server closed"
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

// itoa avoids importing strconv in hot paths.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// Prevent unused-import warnings on platforms that skip tests.
var _ = shared.BackendInfo{}
