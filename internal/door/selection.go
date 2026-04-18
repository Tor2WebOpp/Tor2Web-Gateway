package door

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
	"sync/atomic"

	"gateway/internal/config"
	"gateway/internal/shared"
)

// Selector owns the in-memory mirror-health table and picks redirect
// targets for each slug. It is fed by snapshot.go — UpdateMirrors is
// called on every mirror_snapshot / mirror_upsert / mirror_delete
// event received from the hub.
//
// Safe for concurrent use; the mu lock is held for writes and short
// reads only. The atomic rrCounter keeps round-robin state without
// blocking the hot path.
type Selector struct {
	mu      sync.RWMutex
	mirrors []shared.MirrorInfo

	rrCounter atomic.Uint64

	// randSource is overridable for deterministic tests. When nil the
	// default crypto/rand source is used.
	randSource func(n int) int
}

// NewSelector returns an empty Selector. Callers must feed it mirrors
// via UpdateMirrors before Pick returns anything useful.
func NewSelector() *Selector {
	return &Selector{}
}

// UpdateMirrors replaces the full mirror set atomically. ms is copied
// so the caller can mutate its slice after the call returns.
func (s *Selector) UpdateMirrors(ms []shared.MirrorInfo) {
	out := make([]shared.MirrorInfo, len(ms))
	copy(out, ms)
	s.mu.Lock()
	s.mirrors = out
	s.mu.Unlock()
}

// UpsertMirror adds or replaces a single mirror entry by Host. Used by
// the snapshot client when a single mirror_upsert event lands.
func (s *Selector) UpsertMirror(m shared.MirrorInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.mirrors {
		if s.mirrors[i].Host == m.Host {
			s.mirrors[i] = m
			return
		}
	}
	s.mirrors = append(s.mirrors, m)
}

// RemoveMirror drops the entry with the given Host. A no-op if the
// host is not currently tracked.
func (s *Selector) RemoveMirror(host string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.mirrors {
		if s.mirrors[i].Host == host {
			s.mirrors = append(s.mirrors[:i], s.mirrors[i+1:]...)
			return
		}
	}
}

// Mirrors returns a defensive copy of the current mirror table.
// Exposed for tests and admin tooling.
func (s *Selector) Mirrors() []shared.MirrorInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]shared.MirrorInfo, len(s.mirrors))
	copy(out, s.mirrors)
	return out
}

// Pick returns the host of one candidate mirror matching slug. The
// caller is responsible for composing the full URL (scheme, path,
// query) — returning just the host keeps the Selector free of HTTP
// detail and simplifies testing.
//
// Filtering order matches the spec:
//
//  1. Verdict == "live" (no degraded, no blocked, no unknown).
//  2. !ManualBlock.
//  3. TargetTenants intersection — if the slug lists one or more
//     tenants, the mirror must declare at least one of them in its
//     own TargetTenants field. An empty slug list admits everything.
//  4. ExcludeRegions — mirrors whose BlockedRegions overlap any of
//     the slug's ExcludeRegions are filtered out.
//
// If no mirror survives the filters, Pick returns ok=false. Callers
// translate that into a 503 at the HTTP layer.
func (s *Selector) Pick(slug config.SlugConf) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	candidates := make([]shared.MirrorInfo, 0, len(s.mirrors))
	for _, m := range s.mirrors {
		if !mirrorEligible(m, slug) {
			continue
		}
		candidates = append(candidates, m)
	}
	if len(candidates) == 0 {
		return "", false
	}

	switch slug.Strategy {
	case config.StrategyRoundRobin:
		idx := s.rrCounter.Add(1) - 1
		return candidates[int(idx%uint64(len(candidates)))].Host, true
	case config.StrategyWeighted:
		return pickWeighted(candidates, s.randSource), true
	default: // random
		return pickRandom(candidates, s.randSource), true
	}
}

// mirrorEligible applies the spec-defined filter chain to m for slug.
func mirrorEligible(m shared.MirrorInfo, slug config.SlugConf) bool {
	if m.Verdict != "live" {
		return false
	}
	if m.ManualBlock {
		return false
	}
	if !tenantsMatch(m.TargetTenants, slug.TargetTenants) {
		return false
	}
	if regionBlocked(m.BlockedRegions, slug.ExcludeRegions) {
		return false
	}
	return true
}

// tenantsMatch reports whether slugTenants is either empty (admit all)
// or has at least one element in mirrorTenants.
func tenantsMatch(mirrorTenants, slugTenants []string) bool {
	if len(slugTenants) == 0 {
		return true
	}
	if len(mirrorTenants) == 0 {
		// Slug has a filter list but the mirror declares no tenants —
		// treat as non-match. Operators who want "any tenant" must
		// leave the slug's target_tenants empty.
		return false
	}
	for _, wanted := range slugTenants {
		for _, got := range mirrorTenants {
			if wanted == got {
				return true
			}
		}
	}
	return false
}

// regionBlocked returns true when mirrorBlocked overlaps excludeRegions.
func regionBlocked(mirrorBlocked, excludeRegions []string) bool {
	if len(mirrorBlocked) == 0 || len(excludeRegions) == 0 {
		return false
	}
	for _, blocked := range mirrorBlocked {
		for _, ex := range excludeRegions {
			if blocked == ex {
				return true
			}
		}
	}
	return false
}

// pickRandom chooses one candidate uniformly at random using src or
// crypto/rand when src is nil.
func pickRandom(c []shared.MirrorInfo, src func(int) int) string {
	idx := cryptoRandIntn(len(c), src)
	return c[idx].Host
}

// pickWeighted chooses one candidate with probability proportional to
// its Weight field. Entries with Weight<=0 are treated as weight 1 so
// operators who forget to set weights still get uniform random
// selection rather than zero-probability entries.
func pickWeighted(c []shared.MirrorInfo, src func(int) int) string {
	total := 0
	weights := make([]int, len(c))
	for i, m := range c {
		w := m.Weight
		if w <= 0 {
			w = 1
		}
		weights[i] = w
		total += w
	}
	r := cryptoRandIntn(total, src)
	sum := 0
	for i, w := range weights {
		sum += w
		if r < sum {
			return c[i].Host
		}
	}
	// Defensive: float-precision / empty-weights fallback.
	return c[len(c)-1].Host
}

// cryptoRandIntn returns a uniform integer in [0, n). When src is
// non-nil it is used directly; otherwise crypto/rand is consulted.
// n <= 0 short-circuits to 0 so callers do not need to guard the
// single-element case.
func cryptoRandIntn(n int, src func(int) int) int {
	if n <= 1 {
		return 0
	}
	if src != nil {
		return src(n)
	}
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// Crypto/rand.Reader.Read is documented never to return an
		// error on supported platforms; if it ever does, degrade
		// gracefully to index 0 rather than panicking the door.
		return 0
	}
	u := binary.BigEndian.Uint64(buf[:])
	return int(u % uint64(n))
}
