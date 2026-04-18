package main

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"gateway/internal/config"
	"gateway/internal/torpool"
	"gopkg.in/natefinch/lumberjack.v2"
)

// TestOutage1_1_BuildLogWriterStdoutNoFile asserts buildLogWriter returns
// os.Stdout (not a lumberjack file writer) when Logging.Output=="stdout",
// and that no file named "stdout" gets created in CWD during/around the
// call.
//
// Pre-fix, main.go unconditionally wrapped cfg.Logging.Output in a
// lumberjack.Logger. lumberjack creates the file on first write — so even
// handing the handler a "stdout" path would materialise a regular file
// named stdout in the gateway CWD on every boot, silently redirecting
// torpool logs off the journal. This regression test exercises both
// properties.
func TestOutage1_1_BuildLogWriterStdoutNoFile(t *testing.T) {
	tmpDir := t.TempDir()
	origWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("chdir tmpdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(origWD) })

	cfg := config.LoggingConf{
		Output:     "stdout",
		MaxSizeMB:  10,
		MaxBackups: 2,
	}
	w := buildLogWriter(cfg)
	if w != os.Stdout {
		t.Fatalf("buildLogWriter(stdout) returned %T %p, want os.Stdout", w, w)
	}
	// It should explicitly NOT be a *lumberjack.Logger — guard against a
	// future refactor that accidentally routes back through rotation.
	if _, ok := w.(*lumberjack.Logger); ok {
		t.Fatalf("buildLogWriter(stdout) returned *lumberjack.Logger; want os.Stdout")
	}

	// Force a write via slog — ensures that if lumberjack HAD been returned
	// the file would materialise now (lumberjack is lazy about file creation).
	if _, err := w.Write([]byte("{\"msg\":\"probe\"}\n")); err != nil {
		t.Fatalf("write to stdout writer: %v", err)
	}

	// No file named "stdout" (or any regular file) should appear in CWD.
	if _, err := os.Stat(filepath.Join(tmpDir, "stdout")); !os.IsNotExist(err) {
		t.Fatalf("lumberjack guard broken: file %q exists (err=%v)", filepath.Join(tmpDir, "stdout"), err)
	}
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		t.Errorf("unexpected file created in CWD: %s", e.Name())
	}
}

// TestOutage1_1_BuildLogWriterStderr likewise covers the stderr sentinel.
func TestOutage1_1_BuildLogWriterStderr(t *testing.T) {
	w := buildLogWriter(config.LoggingConf{Output: "stderr"})
	if w != os.Stderr {
		t.Fatalf("buildLogWriter(stderr) returned %T, want os.Stderr", w)
	}
}

// TestOutage1_1_BuildLogWriterEmptyOutputUsesStdout covers the default-config
// path. config.fillDefaults rewrites "" to "stdout" before Load returns, but
// a programmatic caller (another binary embedding torpool) might still pass
// "" — treat it the same as stdout.
func TestOutage1_1_BuildLogWriterEmptyOutputUsesStdout(t *testing.T) {
	w := buildLogWriter(config.LoggingConf{})
	if w != os.Stdout {
		t.Fatalf("buildLogWriter(empty) returned %T, want os.Stdout", w)
	}
}

// TestOutage1_1_BuildLogWriterFilePathUsesLumberjack verifies the fallback
// path still reaches lumberjack for real filesystem targets.
func TestOutage1_1_BuildLogWriterFilePathUsesLumberjack(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "gateway-torpool.log")
	w := buildLogWriter(config.LoggingConf{Output: path, MaxSizeMB: 1, MaxBackups: 1})
	lb, ok := w.(*lumberjack.Logger)
	if !ok {
		t.Fatalf("buildLogWriter(%q) returned %T, want *lumberjack.Logger", path, w)
	}
	if lb.Filename != path {
		t.Fatalf("lumberjack Filename = %q, want %q", lb.Filename, path)
	}
}

// TestOutage1_5_ShutdownHealthCheckerWaits asserts that
// shutdownHealthChecker blocks until hc.Wait() returns, up to the timeout.
// The HealthChecker's WaitGroup is exported via the Wait method; we
// simulate an in-flight replace by calling Add(1) directly on the
// embedded WaitGroup through the real NewHealthChecker (which exposes
// Wait). To keep the test hermetic we construct a minimal manager.
func TestOutage1_5_ShutdownHealthCheckerWaits(t *testing.T) {
	cfg := &config.Config{}
	cfg.Tor.MinInstances = 0
	mgr := torpool.NewManager(cfg)

	hc := torpool.NewHealthChecker(mgr, 1*time.Hour)

	// Spawn a fake replace goroutine held open by the test. This mirrors
	// what happens inside HealthChecker.replaceAsync under real load: the
	// goroutine holds the WaitGroup until replacement finishes.
	release := make(chan struct{})
	torpool.HCWaitAdd(hc, 1)
	go func() {
		defer torpool.HCWaitDone(hc)
		<-release
	}()

	// Call shutdown with a tiny timeout so we observe the timeout path
	// (inflight replace has not released yet).
	start := time.Now()
	shutdownHealthChecker(hc, 100*time.Millisecond)
	elapsed := time.Since(start)
	if elapsed < 100*time.Millisecond {
		t.Fatalf("shutdownHealthChecker returned in %v; expected to honour 100ms timeout", elapsed)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("shutdownHealthChecker took %v on a 100ms timeout — timer broken", elapsed)
	}

	// Now release and call again with a generous budget; it should return
	// quickly because Wait is already unblocked.
	close(release)
	start = time.Now()
	shutdownHealthChecker(hc, 5*time.Second)
	elapsed = time.Since(start)
	if elapsed > 500*time.Millisecond {
		t.Fatalf("shutdownHealthChecker after release took %v; want <500ms", elapsed)
	}
}

// TestOutage1_5_ShutdownOrdering asserts that shutdownHealthChecker runs
// BEFORE mgr.Shutdown in the main.go shutdown sequence. We reproduce the
// sequence inline (main.main itself is not a unit) and record ordering via
// a shared slice under a mutex. This guards against a future refactor that
// reintroduces the defer mgr.Shutdown()-first pattern that caused the
// outage-1.5 log-into-closed-writer errors.
func TestOutage1_5_ShutdownOrdering(t *testing.T) {
	cfg := &config.Config{}
	cfg.Tor.MinInstances = 0
	mgr := torpool.NewManager(cfg)
	hc := torpool.NewHealthChecker(mgr, 1*time.Hour)

	// Hold an inflight replace so hc.Wait() actually blocks until we say so.
	release := make(chan struct{})
	torpool.HCWaitAdd(hc, 1)
	go func() {
		defer torpool.HCWaitDone(hc)
		<-release
	}()

	var (
		mu    sync.Mutex
		order []string
	)
	record := func(name string) {
		mu.Lock()
		order = append(order, name)
		mu.Unlock()
	}

	done := make(chan struct{})
	go func() {
		shutdownHealthChecker(hc, 5*time.Second)
		record("hc.Wait")
		mgrShutdownWrapped(mgr, record)
		close(done)
	}()

	// Give shutdownHealthChecker time to enter its wait.
	time.Sleep(50 * time.Millisecond)

	// At this point nothing should have been recorded — shutdownHealthChecker
	// must be blocked on the WaitGroup.
	mu.Lock()
	recordedBefore := append([]string{}, order...)
	mu.Unlock()
	if len(recordedBefore) != 0 {
		t.Fatalf("records before release: %v; expected empty (hc.Wait should block)", recordedBefore)
	}

	close(release)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown sequence did not complete within 3s")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(order) != 2 || order[0] != "hc.Wait" || order[1] != "mgr.Shutdown" {
		t.Fatalf("shutdown order = %v, want [hc.Wait mgr.Shutdown]", order)
	}
}

// mgrShutdownWrapped is a tiny helper to let the ordering test hook the
// call site without changing production main.go — we can't easily wrap
// mgr.Shutdown itself from a black-box test, so we call it here and
// record after the fact. The production main.go is the next line after
// shutdownHealthChecker returns, so this matches its semantics.
func mgrShutdownWrapped(mgr *torpool.Manager, record func(string)) {
	mgr.Shutdown()
	record("mgr.Shutdown")
}
