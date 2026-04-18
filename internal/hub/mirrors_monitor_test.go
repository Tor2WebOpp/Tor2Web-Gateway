package hub

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeClient is a MonitorClient stand-in whose Results map lets tests dictate
// what each call returns. Count tracks invocations so tests can confirm the
// monitor actually ran. The optional Err lets us assert error propagation.
type fakeClient struct {
	mu      sync.Mutex
	count   int
	results map[string]map[string]NodeCheck
	err     error
}

func newFakeClient(results map[string]map[string]NodeCheck) *fakeClient {
	return &fakeClient{results: results}
}

func (f *fakeClient) CheckNow(ctx context.Context, host string, regions []string, maxNodes int, poll time.Duration, maxWait time.Duration) (map[string]NodeCheck, error) {
	f.mu.Lock()
	f.count++
	if f.err != nil {
		err := f.err
		f.mu.Unlock()
		return nil, err
	}
	r := f.results[host]
	f.mu.Unlock()
	if r == nil {
		return map[string]NodeCheck{}, nil
	}
	out := make(map[string]NodeCheck, len(r))
	for k, v := range r {
		out[k] = v
	}
	return out, nil
}

func (f *fakeClient) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.count
}

func TestMonitor_CheckOnce_UpdatesRegistry(t *testing.T) {
	r, _ := mustMirrors(t)
	ctx := context.Background()
	// Two mirrors: one healthy, one heavily blocked.
	if err := r.Upsert(ctx, sampleMirror("good.example.com")); err != nil {
		t.Fatal(err)
	}
	if err := r.Upsert(ctx, sampleMirror("bad.example.com")); err != nil {
		t.Fatal(err)
	}

	fc := newFakeClient(map[string]map[string]NodeCheck{
		"good.example.com": {
			"n1": {Status: "ok", LatencyMs: 100},
			"n2": {Status: "ok", LatencyMs: 120},
		},
		"bad.example.com": {
			"n1": {Status: "timeout"},
			"n2": {Status: "refused"},
			"n3": {Status: "error"},
		},
	})
	mon := NewMonitor(r, MonitorConfig{
		Enabled:      true,
		Interval:     time.Minute,
		Regions:      []string{"r1"},
		MaxNodes:     5,
		ThresholdPct: 0.5,
		Client:       fc,
	})
	if err := mon.CheckOnce(ctx); err != nil {
		t.Fatalf("CheckOnce: %v", err)
	}
	if got := fc.calls(); got != 2 {
		t.Fatalf("CheckNow call count = %d, want 2", got)
	}

	good, _ := r.Get("good.example.com")
	if good.Verdict != VerdictLive {
		t.Fatalf("good verdict = %q", good.Verdict)
	}
	if len(good.Regions) != 2 {
		t.Fatalf("good regions = %d", len(good.Regions))
	}
	// Check one of the region entries carries the latency.
	n1 := good.Regions["n1"]
	if n1.LatencyMs != 100 || n1.Status != "ok" || n1.At.IsZero() {
		t.Fatalf("good n1 = %+v", n1)
	}

	bad, _ := r.Get("bad.example.com")
	if bad.Verdict != VerdictBlocked {
		t.Fatalf("bad verdict = %q", bad.Verdict)
	}
	if bad.TotalChecked != 3 || bad.BlockedCount != 3 {
		t.Fatalf("bad counters = %d/%d", bad.BlockedCount, bad.TotalChecked)
	}
}

func TestMonitor_CheckOnce_SkipsManuallyBlocked(t *testing.T) {
	r, _ := mustMirrors(t)
	ctx := context.Background()
	if err := r.Upsert(ctx, sampleMirror("active.example.com")); err != nil {
		t.Fatal(err)
	}
	if err := r.ForceBlock(ctx, "frozen.example.com", ""); err != nil {
		t.Fatal(err)
	}

	fc := newFakeClient(map[string]map[string]NodeCheck{
		"active.example.com": {"n1": {Status: "ok"}},
		"frozen.example.com": {"n1": {Status: "ok"}},
	})
	mon := NewMonitor(r, MonitorConfig{
		Enabled:      true,
		Interval:     time.Minute,
		ThresholdPct: 0.5,
		Client:       fc,
	})
	if err := mon.CheckOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := fc.calls(); got != 1 {
		t.Fatalf("expected 1 CheckNow call (manually blocked skipped), got %d", got)
	}
	frozen, _ := r.Get("frozen.example.com")
	if frozen.Verdict != VerdictBlocked || !frozen.ManualBlock {
		t.Fatalf("frozen state changed: %+v", frozen)
	}
}

func TestMonitor_CheckOnce_NoMirrors(t *testing.T) {
	r, _ := mustMirrors(t)
	fc := newFakeClient(nil)
	mon := NewMonitor(r, MonitorConfig{Enabled: true, ThresholdPct: 0.5, Client: fc})
	if err := mon.CheckOnce(context.Background()); err != nil {
		t.Fatalf("CheckOnce: %v", err)
	}
	if got := fc.calls(); got != 0 {
		t.Fatalf("CheckNow called %d times on empty registry", got)
	}
}

func TestMonitor_CheckOnce_Disabled(t *testing.T) {
	r, _ := mustMirrors(t)
	if err := r.Upsert(context.Background(), sampleMirror("x.example.com")); err != nil {
		t.Fatal(err)
	}
	fc := newFakeClient(map[string]map[string]NodeCheck{
		"x.example.com": {"n1": {Status: "ok"}},
	})
	mon := NewMonitor(r, MonitorConfig{Enabled: false, Client: fc})
	if err := mon.CheckOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := fc.calls(); got != 0 {
		t.Fatalf("disabled monitor still called client: %d", got)
	}
}

func TestMonitor_CheckOnce_PropagatesClientError(t *testing.T) {
	r, _ := mustMirrors(t)
	if err := r.Upsert(context.Background(), sampleMirror("e.example.com")); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("boom")
	fc := &fakeClient{err: sentinel}
	mon := NewMonitor(r, MonitorConfig{Enabled: true, ThresholdPct: 0.5, Client: fc})
	err := mon.CheckOnce(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("error chain missing sentinel: %v", err)
	}
}

func TestMonitor_StartStop_CleanExitOnCancel(t *testing.T) {
	r, _ := mustMirrors(t)
	if err := r.Upsert(context.Background(), sampleMirror("t.example.com")); err != nil {
		t.Fatal(err)
	}
	fc := newFakeClient(map[string]map[string]NodeCheck{
		"t.example.com": {"n1": {Status: "ok"}},
	})
	// Short interval so the loop actually ticks at least once during the
	// test window.
	mon := NewMonitor(r, MonitorConfig{
		Enabled:      true,
		Interval:     20 * time.Millisecond,
		ThresholdPct: 0.5,
		Client:       fc,
	})
	ctx, cancel := context.WithCancel(context.Background())
	if err := mon.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Wait until the first check has run.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if fc.calls() >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if fc.calls() == 0 {
		t.Fatal("monitor never ran")
	}

	cancel()
	// Stop should return promptly after ctx cancel.
	doneCh := make(chan struct{})
	go func() {
		mon.Stop()
		close(doneCh)
	}()
	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return after ctx cancel")
	}
}

func TestMonitor_StartStop_DirectStop(t *testing.T) {
	r, _ := mustMirrors(t)
	fc := newFakeClient(nil)
	mon := NewMonitor(r, MonitorConfig{
		Enabled:      true,
		Interval:     50 * time.Millisecond,
		ThresholdPct: 0.5,
		Client:       fc,
	})
	if err := mon.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Give the first run a chance to execute so Stop interrupts the sleep
	// loop rather than the immediate-run path.
	time.Sleep(20 * time.Millisecond)
	doneCh := make(chan struct{})
	go func() {
		mon.Stop()
		close(doneCh)
	}()
	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return")
	}
	// Second stop is a no-op.
	mon.Stop()
}

func TestMonitor_Start_IdempotentAndNilChecks(t *testing.T) {
	r, _ := mustMirrors(t)
	mon := NewMonitor(r, MonitorConfig{})
	if err := mon.Start(context.Background()); err == nil {
		t.Fatal("expected error for nil client")
	}

	fc := newFakeClient(nil)
	mon = NewMonitor(r, MonitorConfig{
		Enabled:      true,
		Interval:     time.Hour,
		ThresholdPct: 0.5,
		Client:       fc,
	})
	if err := mon.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Calling Start twice is a no-op (no error, no extra goroutine).
	if err := mon.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	mon.Stop()
}

func TestMonitor_NewMonitor_NilRegistry(t *testing.T) {
	fc := newFakeClient(nil)
	mon := NewMonitor(nil, MonitorConfig{Client: fc})
	if err := mon.Start(context.Background()); err == nil {
		t.Fatal("expected error for nil registry")
	}
	if err := mon.CheckOnce(context.Background()); err == nil {
		t.Fatal("expected error for nil registry")
	}
}

func TestMonitor_HotReloadSettings(t *testing.T) {
	// When settings are written on disk, the next tick should observe the
	// new values. This is exercised via CheckOnce which resolves settings
	// the same way the loop does.
	r, _ := mustMirrors(t)
	ctx := context.Background()
	if err := r.Upsert(ctx, sampleMirror("hr.example.com")); err != nil {
		t.Fatal(err)
	}
	// First: save settings saying disabled=false with non-zero interval so
	// the monitor applies the file-on-disk path.
	if err := SaveCheckHostSettings(r.DataDir(), CheckHostSettings{
		Enabled:      false,
		Interval:     time.Minute,
		ThresholdPct: 0.5,
	}); err != nil {
		t.Fatal(err)
	}
	fc := newFakeClient(map[string]map[string]NodeCheck{
		"hr.example.com": {"n1": {Status: "ok"}},
	})
	mon := NewMonitor(r, MonitorConfig{Enabled: true, Client: fc})
	if err := mon.CheckOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := fc.calls(); got != 0 {
		t.Fatalf("disabled via disk still ran: %d", got)
	}
	// Flip to enabled via disk only.
	if err := SaveCheckHostSettings(r.DataDir(), CheckHostSettings{
		Enabled:      true,
		Interval:     time.Minute,
		ThresholdPct: 0.5,
	}); err != nil {
		t.Fatal(err)
	}
	if err := mon.CheckOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := fc.calls(); got == 0 {
		t.Fatal("enabled via disk did not take effect")
	}
}

func TestMonitor_ConcurrentRegistryAccess(t *testing.T) {
	// Race-detector smoke test: concurrent CheckOnce (reader) and Upsert
	// (writer) on the same registry must be safe. We deliberately avoid
	// two CheckOnce goroutines racing UpdateHealth on the same host
	// because on Windows two simultaneous rename-over-existing calls can
	// return "Access is denied"; production only runs one monitor tick at
	// a time so same-host write contention never happens in the field.
	r, _ := mustMirrors(t)
	ctx := context.Background()
	if err := r.Upsert(ctx, sampleMirror("p.example.com")); err != nil {
		t.Fatal(err)
	}
	fc := newFakeClient(map[string]map[string]NodeCheck{
		"p.example.com": {"n1": {Status: "ok"}, "n2": {Status: "ok"}},
	})
	mon := NewMonitor(r, MonitorConfig{Enabled: true, ThresholdPct: 0.5, Client: fc})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := mon.CheckOnce(ctx); err != nil {
			t.Errorf("CheckOnce: %v", err)
		}
	}()
	// Reader goroutines hammer Get/List while the checker is running.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = r.List()
				_, _ = r.Get("p.example.com")
			}
		}()
	}
	wg.Wait()

	got, _ := r.Get("p.example.com")
	if got.Verdict != VerdictLive {
		t.Fatalf("final verdict = %q", got.Verdict)
	}
}
