package negcache

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Clock is the minimal time source used by Cache. It exists so tests can
// inject a deterministic clock without depending on real wall time.
type Clock func() time.Time

// Entry is a live blacklist entry returned by Snapshot. ExpiresAt is the
// absolute time at which IsBlacklisted will stop returning true.
type Entry struct {
	Tenant    string
	Onion     string
	ExpiresAt time.Time
}

// counter holds the consecutive-failure tally for one (tenant, onion)
// pair. Access is via atomic.Int64 so RecordFailure can increment from
// many goroutines without a mutex.
type counter struct {
	n atomic.Int64
}

// blacklistEntry is the stored side of a blacklist insertion. The field
// is written once at insertion time; subsequent reads observe the same
// value until Sweep or RecordSuccess deletes it.
type blacklistEntry struct {
	expiresAt time.Time
}

// Cache tracks consecutive per-(tenant, onion) failures and exposes a
// blacklist of backends whose failure count recently crossed a
// configured threshold.
//
// Zero value is not ready for use; callers must construct via NewCache.
type Cache struct {
	counters  sync.Map // key -> *counter
	blacklist sync.Map // key -> *blacklistEntry

	mu        sync.RWMutex
	ttl       time.Duration
	threshold int

	clock Clock
}

// NewCache returns a Cache with the given defaults. defaultTTL applies to
// every blacklist entry written until Configure is called; failureThreshold
// is the number of consecutive failures at which RecordFailure flips an
// entry into the blacklist. Non-positive values are preserved verbatim,
// which effectively disables the feature until Configure is called with
// sensible defaults.
func NewCache(defaultTTL time.Duration, failureThreshold int) *Cache {
	return &Cache{
		ttl:       defaultTTL,
		threshold: failureThreshold,
		clock:     time.Now,
	}
}

// SetClock replaces the cache's time source. It is intended for tests
// that need deterministic expiry behaviour; production code should leave
// the default time.Now in place. The supplied clock must be safe for
// concurrent use and must be monotonic for correctness, as all deadline
// comparisons read it without further synchronisation.
func (c *Cache) SetClock(clock Clock) {
	if clock == nil {
		clock = time.Now
	}
	c.mu.Lock()
	c.clock = clock
	c.mu.Unlock()
}

// now reads the current clock under the config lock so Configure and
// clock replacement stay coherent. The call is cheap: a single RLock
// followed by one function call.
func (c *Cache) now() time.Time {
	c.mu.RLock()
	clk := c.clock
	c.mu.RUnlock()
	return clk()
}

// Configure hot-reloads the default TTL and failure threshold. Existing
// blacklist entries retain the TTL they were written with; only new
// insertions observe the new defaults. Threshold changes take effect on
// the next RecordFailure call for any given pair.
func (c *Cache) Configure(defaultTTL time.Duration, failureThreshold int) {
	c.mu.Lock()
	c.ttl = defaultTTL
	c.threshold = failureThreshold
	c.mu.Unlock()
}

// defaults returns the current TTL and threshold in one lock cycle.
func (c *Cache) defaults() (time.Duration, int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ttl, c.threshold
}

// keyFor forms the composite sync.Map key. NUL is safe because neither a
// tenant host nor a v3 onion address may legally contain it.
func keyFor(tenant, onion string) string {
	return tenant + "\x00" + onion
}

// splitKey reverses keyFor. It returns tenant, onion, ok; ok is false if
// the stored key is malformed (which never happens under normal writes
// but is defended against so Snapshot cannot panic on corruption).
func splitKey(key string) (string, string, bool) {
	for i := 0; i < len(key); i++ {
		if key[i] == 0 {
			return key[:i], key[i+1:], true
		}
	}
	return "", "", false
}

// RecordFailure increments the consecutive-failure counter for the given
// pair. When the counter reaches the currently configured threshold the
// pair is inserted into the blacklist for the currently configured TTL.
// If the pair is already blacklisted the counter and the blacklist
// deadline are left unchanged; RecordSuccess is the only path that
// clears the state.
func (c *Cache) RecordFailure(tenant, onion string) {
	ttl, threshold := c.defaults()
	if threshold <= 0 {
		return
	}

	key := keyFor(tenant, onion)

	// If already blacklisted and unexpired, this failure is redundant.
	if _, ok := c.blacklist.Load(key); ok {
		if c.IsBlacklisted(tenant, onion) {
			return
		}
	}

	ctr := c.loadOrStoreCounter(key)
	n := ctr.n.Add(1)
	if n < int64(threshold) {
		return
	}
	// Threshold crossed: write the blacklist entry. LoadOrStore keeps the
	// first insertion's deadline; concurrent crossers observe the same.
	if ttl > 0 {
		c.blacklist.LoadOrStore(key, &blacklistEntry{
			expiresAt: c.now().Add(ttl),
		})
	}
}

// loadOrStoreCounter returns the existing counter for key or installs a
// fresh one. The two-step pattern (Load then LoadOrStore) avoids
// allocating a new counter on the common hit path.
func (c *Cache) loadOrStoreCounter(key string) *counter {
	if v, ok := c.counters.Load(key); ok {
		return v.(*counter)
	}
	fresh := &counter{}
	actual, _ := c.counters.LoadOrStore(key, fresh)
	return actual.(*counter)
}

// RecordSuccess resets the counter to zero and removes any active
// blacklist entry for the given pair. Cheap when the pair was never
// seen: one failed Load and no writes.
func (c *Cache) RecordSuccess(tenant, onion string) {
	key := keyFor(tenant, onion)
	if v, ok := c.counters.Load(key); ok {
		v.(*counter).n.Store(0)
	}
	c.blacklist.Delete(key)
}

// IsBlacklisted reports whether the pair currently has an unexpired
// blacklist entry. Expired entries are reported as not blacklisted and
// are reclaimed by the next Sweep (or eagerly on access for tidiness).
func (c *Cache) IsBlacklisted(tenant, onion string) bool {
	key := keyFor(tenant, onion)
	v, ok := c.blacklist.Load(key)
	if !ok {
		return false
	}
	e := v.(*blacklistEntry)
	if c.now().Before(e.expiresAt) {
		return true
	}
	// Tidy up the expired entry so a caller that repeatedly polls a dead
	// onion doesn't keep paying the cost of loading it.
	c.blacklist.CompareAndDelete(key, v)
	return false
}

// Sweep removes every blacklist entry whose deadline has passed. It
// returns the number of entries removed; the returned value is useful
// to operators sampling the sweep loop for sizing hints.
func (c *Cache) Sweep() int {
	now := c.now()
	removed := 0
	c.blacklist.Range(func(k, v any) bool {
		e := v.(*blacklistEntry)
		if !now.Before(e.expiresAt) {
			if c.blacklist.CompareAndDelete(k, v) {
				removed++
			}
		}
		return true
	})
	return removed
}

// Snapshot returns a deterministic copy of the current live blacklist
// sorted by (tenant, onion) so that admin-UI rendering is stable across
// calls. Expired entries are filtered out but not removed; call Sweep
// to reclaim them.
func (c *Cache) Snapshot() []Entry {
	now := c.now()
	out := make([]Entry, 0)
	c.blacklist.Range(func(k, v any) bool {
		keyStr, okKey := k.(string)
		if !okKey {
			return true
		}
		tenant, onion, ok := splitKey(keyStr)
		if !ok {
			return true
		}
		e := v.(*blacklistEntry)
		if !now.Before(e.expiresAt) {
			return true
		}
		out = append(out, Entry{
			Tenant:    tenant,
			Onion:     onion,
			ExpiresAt: e.expiresAt,
		})
		return true
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].Tenant != out[j].Tenant {
			return out[i].Tenant < out[j].Tenant
		}
		return out[i].Onion < out[j].Onion
	})
	return out
}
