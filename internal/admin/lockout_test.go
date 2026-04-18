package admin

import (
	"context"
	"sync"
	"testing"
	"time"
)

func defaultLockoutCfg() LockoutConfig {
	return LockoutConfig{
		SoftThreshold: 3,
		SoftWindow:    60 * time.Second,
		SoftBackoff:   30 * time.Second,
		HardThreshold: 10,
		HardWindow:    10 * time.Minute,
		HardBan:       time.Hour,
	}
}

func TestLockout_BelowSoftThreshold(t *testing.T) {
	l := NewLockout(defaultLockoutCfg())
	t0 := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	l.SetClock(func() time.Time { return t0 })

	if got := l.RecordFailure("ip"); got != StateAllowed {
		t.Fatalf("after 1 failure: state = %v, want StateAllowed", got)
	}
	if got := l.RecordFailure("ip"); got != StateAllowed {
		t.Fatalf("after 2 failures: state = %v, want StateAllowed", got)
	}
}

func TestLockout_SoftThresholdTrips(t *testing.T) {
	l := NewLockout(defaultLockoutCfg())
	t0 := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	clock := t0
	l.SetClock(func() time.Time { return clock })

	for i := 0; i < 3; i++ {
		l.RecordFailure("ip")
		clock = clock.Add(time.Second)
	}
	// rewind clock so check happens within window after 3rd failure
	clock = t0.Add(2 * time.Second)
	if got := l.Check("ip"); got != StateSoftBackoff {
		t.Fatalf("after 3 failures in window: state = %v, want StateSoftBackoff", got)
	}
}

func TestLockout_SoftBackoffShadowsAdditionalFailures(t *testing.T) {
	l := NewLockout(defaultLockoutCfg())
	t0 := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	clock := t0
	l.SetClock(func() time.Time { return clock })

	for i := 0; i < 3; i++ {
		l.RecordFailure("ip")
	}
	// Inside backoff window (30s default).
	clock = t0.Add(10 * time.Second)
	if got := l.Check("ip"); got != StateSoftBackoff {
		t.Fatalf("Check during backoff: state = %v, want StateSoftBackoff", got)
	}
	// New failure during backoff doesn't drop below backoff.
	if got := l.RecordFailure("ip"); got != StateSoftBackoff {
		t.Fatalf("RecordFailure during backoff: state = %v, want StateSoftBackoff", got)
	}
}

func TestLockout_SoftWindowSlides(t *testing.T) {
	cfg := defaultLockoutCfg()
	l := NewLockout(cfg)
	t0 := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	clock := t0
	l.SetClock(func() time.Time { return clock })

	// 2 failures at t0
	l.RecordFailure("ip")
	l.RecordFailure("ip")
	// One more, but well outside the soft window from the first two.
	clock = t0.Add(2 * cfg.SoftWindow)
	if got := l.RecordFailure("ip"); got != StateAllowed {
		t.Fatalf("3rd failure after window slide: state = %v, want StateAllowed", got)
	}
}

func TestLockout_HardThresholdTrips(t *testing.T) {
	cfg := defaultLockoutCfg()
	l := NewLockout(cfg)
	t0 := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	clock := t0
	l.SetClock(func() time.Time { return clock })

	// Spread 10 failures over the hard window so the soft one is also
	// crossed at some points; the final state should be hard-banned.
	step := cfg.HardWindow / 10
	for i := 0; i < 10; i++ {
		l.RecordFailure("ip")
		clock = clock.Add(step)
	}
	// Move just past the last failure so we're inside the ban.
	clock = clock.Add(time.Second)
	if got := l.Check("ip"); got != StateHardBanned {
		t.Fatalf("after 10 failures in hard window: state = %v, want StateHardBanned", got)
	}
}

func TestLockout_RecordSuccessResets(t *testing.T) {
	l := NewLockout(defaultLockoutCfg())
	t0 := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	l.SetClock(func() time.Time { return t0 })

	for i := 0; i < 3; i++ {
		l.RecordFailure("ip")
	}
	if got := l.Check("ip"); got != StateSoftBackoff {
		t.Fatalf("setup: state = %v, want StateSoftBackoff", got)
	}
	l.RecordSuccess("ip")
	if got := l.Check("ip"); got != StateAllowed {
		t.Fatalf("after RecordSuccess: state = %v, want StateAllowed", got)
	}
}

func TestLockout_RecordSuccessClearsHardBan(t *testing.T) {
	cfg := defaultLockoutCfg()
	l := NewLockout(cfg)
	t0 := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	l.SetClock(func() time.Time { return t0 })

	for i := 0; i < cfg.HardThreshold; i++ {
		l.RecordFailure("ip")
	}
	if got := l.Check("ip"); got != StateHardBanned {
		t.Fatalf("setup: state = %v, want StateHardBanned", got)
	}
	l.RecordSuccess("ip")
	if got := l.Check("ip"); got != StateAllowed {
		t.Fatalf("after RecordSuccess: state = %v, want StateAllowed", got)
	}
}

func TestLockout_StaleEntriesPrunedByGC(t *testing.T) {
	cfg := defaultLockoutCfg()
	l := NewLockout(cfg)
	t0 := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	clock := t0
	l.SetClock(func() time.Time { return clock })

	l.RecordFailure("ip")
	// Move clock far past the hard window so the entry is eligible for
	// pruning.
	clock = t0.Add(cfg.HardWindow + cfg.HardBan + time.Hour)
	l.gcOnce()

	l.mu.Lock()
	_, present := l.entries["ip"]
	l.mu.Unlock()
	if present {
		t.Fatal("stale entry should have been pruned by gcOnce")
	}
}

func TestLockout_GCKeepsActiveBan(t *testing.T) {
	cfg := defaultLockoutCfg()
	l := NewLockout(cfg)
	t0 := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	clock := t0
	l.SetClock(func() time.Time { return clock })

	for i := 0; i < cfg.HardThreshold; i++ {
		l.RecordFailure("ip")
	}
	// Move clock so failures expire from the window but the ban is
	// still active.
	clock = t0.Add(cfg.HardWindow + time.Minute)
	l.gcOnce()

	l.mu.Lock()
	_, present := l.entries["ip"]
	l.mu.Unlock()
	if !present {
		t.Fatal("entry with active ban must not be pruned")
	}
}

func TestLockout_StartGCStopsOnContextCancel(t *testing.T) {
	l := NewLockout(defaultLockoutCfg())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		l.StartGC(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("StartGC did not return after context cancel")
	}
}

func TestLockout_ConcurrentAccess(t *testing.T) {
	l := NewLockout(defaultLockoutCfg())

	const workers = 16
	const ops = 200
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ip := "ip"
			if id%2 == 0 {
				ip = "ip-other"
			}
			for j := 0; j < ops; j++ {
				if j%5 == 0 {
					l.RecordSuccess(ip)
				} else {
					l.RecordFailure(ip)
				}
				_ = l.Check(ip)
			}
		}(i)
	}
	wg.Wait()
}
