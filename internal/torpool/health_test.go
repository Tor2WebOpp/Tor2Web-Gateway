package torpool

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestFailureTracker_MarkDead(t *testing.T) {
	ft := &failureTracker{threshold: 3}

	ft.recordFailure()
	if ft.isDead() {
		t.Fatal("should not be dead after 1 failure")
	}

	ft.recordFailure()
	if ft.isDead() {
		t.Fatal("should not be dead after 2 failures")
	}

	ft.recordFailure()
	if !ft.isDead() {
		t.Fatal("should be dead after 3 failures")
	}
}

func TestFailureTracker_ResetOnSuccess(t *testing.T) {
	ft := &failureTracker{threshold: 3}

	ft.recordFailure()
	ft.recordFailure()
	ft.recordSuccess() // resets counter to 0
	ft.recordFailure() // counter is now 1

	if ft.isDead() {
		t.Fatal("should not be dead: 2 failures, then 1 success, then 1 failure = only 1 consecutive failure")
	}
}

// TestHealthChecker_ForgetPortClearsAllMaps is the bug 7.3 regression
// guard. A scale-down on port 9050 must leave no trackers, probe
// transports, replace-in-flight flags, or quarantine entries so that a
// scale-up rebinding 9050 starts with fresh state.
func TestHealthChecker_ForgetPortClearsAllMaps(t *testing.T) {
	hc := &HealthChecker{}
	const port = 9050

	// Seed every map with a sentinel entry for the port.
	tr := hc.trackerFor(port) // seeds trackers
	tr.recordFailure()
	tr.recordFailure()
	hc.probeTransports.Store(port, struct{}{}) // simplified stub
	replFlag := &atomic.Bool{}
	replFlag.Store(true)
	hc.replacing.Store(port, replFlag)
	hc.quarantined.Store(port, &quarantineEntry{
		since:     time.Now(),
		expiresAt: time.Now().Add(time.Minute),
	})

	// Sanity check: all four maps hold something for this port.
	if _, ok := hc.trackers.Load(port); !ok {
		t.Fatal("setup: trackers missing")
	}
	if _, ok := hc.probeTransports.Load(port); !ok {
		t.Fatal("setup: probeTransports missing")
	}
	if _, ok := hc.replacing.Load(port); !ok {
		t.Fatal("setup: replacing missing")
	}
	if _, ok := hc.quarantined.Load(port); !ok {
		t.Fatal("setup: quarantined missing")
	}

	// ForgetPort must clear every map entry for the port. Note the
	// probe transport path is a bit special — the stub we stored above
	// is not an *http.Transport, so removeProbeTransport would panic
	// if it tried to type-assert. Swap in a real transport before the
	// call so we exercise the real cleanup path, not just the delete.
	hc.probeTransports.Delete(port)
	if _, err := hc.getProbeTransport(port); err != nil {
		t.Fatalf("getProbeTransport setup: %v", err)
	}

	hc.ForgetPort(port)

	if _, ok := hc.trackers.Load(port); ok {
		t.Error("ForgetPort: trackers entry still present")
	}
	if _, ok := hc.probeTransports.Load(port); ok {
		t.Error("ForgetPort: probeTransports entry still present")
	}
	if _, ok := hc.replacing.Load(port); ok {
		t.Error("ForgetPort: replacing entry still present")
	}
	if _, ok := hc.quarantined.Load(port); ok {
		t.Error("ForgetPort: quarantined entry still present")
	}
}
