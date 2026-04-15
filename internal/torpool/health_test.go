package torpool

import (
	"testing"
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
