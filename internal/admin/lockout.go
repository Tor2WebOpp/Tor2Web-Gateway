package admin

import (
	"context"
	"sync"
	"time"
)

// lockoutGCInterval is the period at which the Lockout goroutine
// scans entries to drop fully-stale ones (no failures in HardWindow
// AND no active ban).
const lockoutGCInterval = 60 * time.Second

// State enumerates the lockout decisions for an IP-hash key.
type State int

const (
	// StateAllowed indicates the IP is below all thresholds and may
	// attempt a gate validation.
	StateAllowed State = iota
	// StateSoftBackoff indicates the IP has tripped the short-window
	// counter and is in a brief cooldown.
	StateSoftBackoff
	// StateHardBanned indicates the IP has tripped the long-window
	// counter and is banned for the full HardBan duration.
	StateHardBanned
)

// LockoutConfig carries the four sliding-window parameters and two
// state durations. The package does not impose hard defaults — the
// gateway bootstrap supplies values from configuration.
type LockoutConfig struct {
	SoftThreshold int           // 3
	SoftWindow    time.Duration // 60s
	SoftBackoff   time.Duration // 30s
	HardThreshold int           // 10
	HardWindow    time.Duration // 10min
	HardBan       time.Duration // 1h
}

// entry is the per-IP-hash bookkeeping. failures is kept sorted oldest
// first; compaction drops timestamps older than HardWindow on every
// modification. softUntil and hardUntil are absolute deadlines, zero
// when no ban is in effect.
type entry struct {
	failures  []time.Time
	softUntil time.Time
	hardUntil time.Time
}

// Lockout tracks failed admin gate attempts per IP hash and decides
// whether the IP may attempt entry. It is safe for concurrent use.
type Lockout struct {
	cfg LockoutConfig

	mu      sync.Mutex
	entries map[string]*entry

	// nowFn is the clock used for window comparisons. Tests override
	// it for deterministic verification; the zero value resolves to
	// time.Now.
	nowFn func() time.Time
}

// NewLockout returns a Lockout configured by cfg. The configuration
// is copied — later mutations to the caller's struct have no effect.
func NewLockout(cfg LockoutConfig) *Lockout {
	return &Lockout{
		cfg:     cfg,
		entries: make(map[string]*entry),
	}
}

// SetClock replaces the internal now function. Intended for tests.
// A nil clock restores time.Now.
func (l *Lockout) SetClock(now func() time.Time) {
	l.mu.Lock()
	l.nowFn = now
	l.mu.Unlock()
}

func (l *Lockout) now() time.Time {
	if l.nowFn != nil {
		return l.nowFn()
	}
	return time.Now()
}

// RecordFailure logs a failed attempt for ipHash and returns the
// resulting state AFTER the failure has been recorded. The state is
// computed against both the soft and hard thresholds; if both trip
// simultaneously, StateHardBanned wins.
func (l *Lockout) RecordFailure(ipHash string) State {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	e, ok := l.entries[ipHash]
	if !ok {
		e = &entry{}
		l.entries[ipHash] = e
	}

	// Append the new failure, then compact timestamps older than the
	// hard window — the longest window we care about.
	e.failures = append(e.failures, now)
	cutoff := now.Add(-l.cfg.HardWindow)
	keep := e.failures[:0]
	for _, ts := range e.failures {
		if !ts.Before(cutoff) {
			keep = append(keep, ts)
		}
	}
	e.failures = keep

	// Hard window count (everything still in the slice).
	hardCount := len(e.failures)
	// Soft window count.
	softCutoff := now.Add(-l.cfg.SoftWindow)
	softCount := 0
	for _, ts := range e.failures {
		if !ts.Before(softCutoff) {
			softCount++
		}
	}

	if l.cfg.HardThreshold > 0 && hardCount >= l.cfg.HardThreshold {
		e.hardUntil = now.Add(l.cfg.HardBan)
	}
	if l.cfg.SoftThreshold > 0 && softCount >= l.cfg.SoftThreshold {
		// Only extend the existing softUntil if it's later than now;
		// otherwise set a fresh backoff window.
		newUntil := now.Add(l.cfg.SoftBackoff)
		if newUntil.After(e.softUntil) {
			e.softUntil = newUntil
		}
	}

	return l.stateLocked(e, now)
}

// RecordSuccess clears all failures, the soft backoff and the hard
// ban for the supplied IP hash. The entry itself is removed from the
// map so the keyspace stays small.
func (l *Lockout) RecordSuccess(ipHash string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, ipHash)
}

// Check returns the current state for ipHash without recording a new
// failure. Hard ban shadows soft backoff: a hard-banned IP reports
// StateHardBanned regardless of soft state.
func (l *Lockout) Check(ipHash string) State {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[ipHash]
	if !ok {
		return StateAllowed
	}
	return l.stateLocked(e, l.now())
}

// stateLocked computes the active state for an entry. Caller must
// hold l.mu.
func (l *Lockout) stateLocked(e *entry, now time.Time) State {
	if e.hardUntil.After(now) {
		return StateHardBanned
	}
	if e.softUntil.After(now) {
		return StateSoftBackoff
	}
	return StateAllowed
}

// StartGC runs an eviction loop in the current goroutine until ctx is
// cancelled. Stale entries (no failures inside HardWindow and no
// active ban) are dropped on every tick.
func (l *Lockout) StartGC(ctx context.Context) {
	t := time.NewTicker(lockoutGCInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.gcOnce()
		}
	}
}

// gcOnce sweeps stale entries in a single pass under the write lock.
// An entry is stale when both ban deadlines are in the past AND every
// failure timestamp predates the hard window.
func (l *Lockout) gcOnce() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	cutoff := now.Add(-l.cfg.HardWindow)
	for k, e := range l.entries {
		if e.hardUntil.After(now) || e.softUntil.After(now) {
			continue
		}
		// Compact failures while we're here.
		keep := e.failures[:0]
		for _, ts := range e.failures {
			if !ts.Before(cutoff) {
				keep = append(keep, ts)
			}
		}
		e.failures = keep
		if len(e.failures) == 0 {
			delete(l.entries, k)
		}
	}
}
