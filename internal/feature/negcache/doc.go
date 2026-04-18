// Package negcache implements the backend-selection helper side of the
// "negative_cache" feature: tracking consecutive failures per
// (tenant, onion) pair and marking a backend as blacklisted for a
// configurable TTL once a threshold is exceeded.
//
// This package is intentionally not an HTTP middleware. It exposes a
// Cache value consulted by the proxy backend-selection path to skip
// recently-failed onions, and mutated by the TorTransport retry loop on
// each attempt's outcome. Wave-3 integration wires RecordFailure and
// RecordSuccess into that loop; wave-1 (this package) provides the
// data structure and its concurrency-safe semantics.
//
// Semantics:
//
//   - RecordFailure(tenant, onion) increments a counter for the pair.
//     When the counter reaches failure_threshold the pair is inserted
//     into the blacklist for default_ttl from the time of insertion.
//     Subsequent failures while already blacklisted refresh neither
//     the TTL nor the counter — the entry simply remains blacklisted
//     until the existing deadline elapses.
//   - RecordSuccess(tenant, onion) resets the counter to zero and
//     removes any blacklist entry. A backend that recovers is
//     immediately eligible again.
//   - IsBlacklisted(tenant, onion) returns true iff an unexpired entry
//     exists. Expired entries are treated as absent; Sweep reclaims
//     their storage on demand.
//   - Configure(ttl, threshold) hot-reloads the defaults. Existing
//     entries retain the TTL they were written with; only subsequent
//     insertions use the new values. Thresholds take effect on the
//     next RecordFailure call.
//   - Sweep() removes expired entries in bulk and returns the number
//     removed; it is intended to be called periodically by a
//     background goroutine owned by the hosting process.
//   - Snapshot() returns a stable copy of the current live blacklist
//     suitable for rendering in an admin UI.
//
// Concurrency: counters and blacklist entries live in two independent
// sync.Map instances keyed by "tenant\x00onion". Defaults are guarded
// by an RWMutex so Configure may run concurrently with reads. No lock
// spans a user-visible operation: the hot path is lock-free aside from
// the RLock held briefly while reading the current defaults.
package negcache
