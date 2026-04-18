package ttlblock

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

// saltLen is the number of bytes used for the per-install salt when
// salted_hashes is enabled.
const saltLen = 32

// entriesBucket holds one row per blocked (tenant, ip) pair. meta holds
// global store metadata: currently only the salt.
var (
	entriesBucket = []byte("entries")
	metaBucket    = []byte("meta")
	saltKey       = []byte("salt")
)

// Entry is the on-disk record for a single blocklist hit.
type Entry struct {
	Tenant       string    `json:"tenant"`
	IPOrHash     string    `json:"ip_or_hash"`
	BlockedUntil time.Time `json:"blocked_until"`
	Reason       string    `json:"reason"`
}

// Store is the persistent blocklist backend.
//
// A Store is safe for concurrent use by multiple goroutines. All state
// lives in the BoltDB file; the Store only caches the salt in memory.
type Store struct {
	db *bolt.DB

	// salt is the random per-install salt used to derive on-disk keys
	// when salted hashing is enabled. Empty when the store was opened
	// without a salt file.
	salt []byte

	// now is the clock used for TTL comparisons. Tests override it for
	// deterministic expiry verification. Always resolved through the
	// Now helper; the nil zero value means time.Now.
	nowMu sync.RWMutex
	now   func() time.Time
}

// OpenStore opens or creates the BoltDB file at path. When saltFile is
// non-empty, the per-install salt is read from disk; if the file does
// not exist a fresh 32-byte salt is generated, written with 0600
// permissions, and also mirrored into the "meta" bucket so that
// salted-hash keys survive a deleted salt file as long as the DB is
// intact.
func OpenStore(path string, saltFile string) (*Store, error) {
	if path == "" {
		return nil, errors.New("ttlblock: store path is required")
	}

	// Ensure the parent directory exists so callers can hand us a
	// fresh path like /var/lib/gateway/ttlblock.db without pre-work.
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("ttlblock: mkdir %s: %w", dir, err)
		}
	}

	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("ttlblock: open bolt: %w", err)
	}

	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(entriesBucket); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(metaBucket); err != nil {
			return err
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ttlblock: init buckets: %w", err)
	}

	s := &Store{db: db}

	if saltFile != "" {
		salt, err := loadOrCreateSalt(db, saltFile)
		if err != nil {
			_ = db.Close()
			return nil, err
		}
		s.salt = salt
	}

	return s, nil
}

// loadOrCreateSalt returns a stable 32-byte salt. Preference order:
// saltFile on disk → "meta"/"salt" in the DB → generate fresh. Whichever
// source yielded the salt is copied into the other, so the two stay in
// sync after the first successful open.
func loadOrCreateSalt(db *bolt.DB, saltFile string) ([]byte, error) {
	diskSalt, diskErr := os.ReadFile(saltFile)
	if diskErr != nil && !errors.Is(diskErr, os.ErrNotExist) {
		return nil, fmt.Errorf("ttlblock: read salt %s: %w", saltFile, diskErr)
	}
	diskSalt = decodeSaltMaybeHex(diskSalt)

	var dbSalt []byte
	if err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(metaBucket)
		if b == nil {
			return nil
		}
		if v := b.Get(saltKey); len(v) > 0 {
			dbSalt = append(dbSalt, v...)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	var salt []byte
	switch {
	case len(diskSalt) == saltLen:
		salt = diskSalt
	case len(dbSalt) == saltLen:
		salt = dbSalt
	default:
		salt = make([]byte, saltLen)
		if _, err := rand.Read(salt); err != nil {
			return nil, fmt.Errorf("ttlblock: generate salt: %w", err)
		}
	}

	// Persist back to disk if missing/different. We always write hex so
	// that operators inspecting the file see something they can verify.
	if !bytesEqual(diskSalt, salt) {
		if err := os.MkdirAll(filepath.Dir(saltFile), 0o700); err != nil {
			return nil, fmt.Errorf("ttlblock: mkdir %s: %w", filepath.Dir(saltFile), err)
		}
		if err := os.WriteFile(saltFile, []byte(hex.EncodeToString(salt)), 0o600); err != nil {
			return nil, fmt.Errorf("ttlblock: write salt %s: %w", saltFile, err)
		}
	}
	if !bytesEqual(dbSalt, salt) {
		if err := db.Update(func(tx *bolt.Tx) error {
			b, err := tx.CreateBucketIfNotExists(metaBucket)
			if err != nil {
				return err
			}
			return b.Put(saltKey, salt)
		}); err != nil {
			return nil, err
		}
	}

	return salt, nil
}

// decodeSaltMaybeHex accepts either a raw 32-byte salt or a hex-encoded
// 64-character representation. Returns nil if neither shape fits.
func decodeSaltMaybeHex(raw []byte) []byte {
	if len(raw) == saltLen {
		out := make([]byte, saltLen)
		copy(out, raw)
		return out
	}
	// Trim trailing newline if present (many editors add one).
	for len(raw) > 0 && (raw[len(raw)-1] == '\n' || raw[len(raw)-1] == '\r') {
		raw = raw[:len(raw)-1]
	}
	if len(raw) == 2*saltLen {
		out := make([]byte, saltLen)
		if _, err := hex.Decode(out, raw); err == nil {
			return out
		}
	}
	return nil
}

// bytesEqual returns true when the two byte slices have identical
// contents. Inlined to avoid pulling the bytes package.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// SetClock replaces the internal now function. Intended for tests.
// A nil clock restores time.Now.
func (s *Store) SetClock(now func() time.Time) {
	s.nowMu.Lock()
	s.now = now
	s.nowMu.Unlock()
}

// Now returns the store's current time. External packages generally do
// not need this; it is exported primarily so tests using a fake clock
// can observe the same time the store sees.
func (s *Store) Now() time.Time {
	s.nowMu.RLock()
	fn := s.now
	s.nowMu.RUnlock()
	if fn != nil {
		return fn()
	}
	return time.Now()
}

// Close releases the underlying BoltDB handle.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// SaltedHashes reports whether the store is storing hashed keys.
func (s *Store) SaltedHashes() bool {
	return len(s.salt) == saltLen
}

// keyFor derives the on-disk key for (tenant, ip). When salted_hashes is
// enabled the IP is replaced by a hex-encoded sha256(ip||salt). The NUL
// byte separator guarantees unambiguous tenant boundaries.
func (s *Store) keyFor(tenant, ip string) []byte {
	ipPart := ip
	if len(s.salt) == saltLen {
		h := sha256.New()
		h.Write([]byte(ip))
		h.Write(s.salt)
		ipPart = hex.EncodeToString(h.Sum(nil))
	}
	return []byte(fmt.Sprintf("%s\x00%s", tenant, ipPart))
}

// Add inserts or refreshes a blocklist entry for (tenant, ip).
//
// A zero ttl is rejected — callers should substitute the tenant's
// effective default_ttl before calling. max indicates the LRU cap;
// when positive, Add trims the oldest entries (lowest BlockedUntil)
// for the given tenant once the total exceeds max.
func (s *Store) Add(tenant, ip string, ttl time.Duration, reason string, max int) error {
	if tenant == "" {
		return errors.New("ttlblock: tenant is required")
	}
	if ip == "" {
		return errors.New("ttlblock: ip is required")
	}
	if ttl <= 0 {
		return errors.New("ttlblock: ttl must be positive")
	}

	key := s.keyFor(tenant, ip)
	entry := Entry{
		Tenant:       tenant,
		IPOrHash:     extractIPPart(key, tenant),
		BlockedUntil: s.Now().Add(ttl),
		Reason:       reason,
	}
	encoded, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("ttlblock: marshal entry: %w", err)
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(entriesBucket)
		if b == nil {
			return errors.New("ttlblock: entries bucket missing")
		}
		if err := b.Put(key, encoded); err != nil {
			return err
		}
		if max > 0 {
			return trimTenantLRU(b, tenant, max)
		}
		return nil
	})
}

// extractIPPart returns everything after the tenant\x00 prefix. The
// caller-supplied tenant is trusted to match the prefix of key; this is
// only used to populate the Entry's IPOrHash field for list output.
func extractIPPart(key []byte, tenant string) string {
	prefix := tenant + "\x00"
	if len(key) < len(prefix) {
		return string(key)
	}
	return string(key[len(prefix):])
}

// Contains reports whether (tenant, ip) currently has an unexpired
// blocklist row.
//
// Expired rows still return false but are not actively deleted — that
// is the Sweep goroutine's job. Contains is therefore safe to call on
// read-only transactions.
func (s *Store) Contains(tenant, ip string) bool {
	if s == nil || s.db == nil || tenant == "" || ip == "" {
		return false
	}
	key := s.keyFor(tenant, ip)
	now := s.Now()

	hit := false
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(entriesBucket)
		if b == nil {
			return nil
		}
		v := b.Get(key)
		if v == nil {
			return nil
		}
		var e Entry
		if err := json.Unmarshal(v, &e); err != nil {
			return nil
		}
		if e.BlockedUntil.After(now) {
			hit = true
		}
		return nil
	})
	if err != nil {
		return false
	}
	return hit
}

// Remove deletes the (tenant, ip) entry if present. Removing a missing
// entry is not an error.
func (s *Store) Remove(tenant, ip string) error {
	if tenant == "" || ip == "" {
		return nil
	}
	key := s.keyFor(tenant, ip)
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(entriesBucket)
		if b == nil {
			return nil
		}
		return b.Delete(key)
	})
}

// List returns every entry whose key starts with "<tenant>\x00". The
// slice is sorted by BlockedUntil ascending (oldest first).
func (s *Store) List(tenant string) []Entry {
	if tenant == "" {
		return nil
	}
	prefix := []byte(tenant + "\x00")
	var out []Entry
	_ = s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(entriesBucket)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.Seek(prefix); k != nil && hasPrefix(k, prefix); k, v = c.Next() {
			var e Entry
			if err := json.Unmarshal(v, &e); err != nil {
				continue
			}
			out = append(out, e)
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool {
		return out[i].BlockedUntil.Before(out[j].BlockedUntil)
	})
	return out
}

// Sweep deletes every entry whose BlockedUntil is at or before the
// current clock. Intended to be called periodically by a sweeper
// goroutine — roughly every 10 minutes in the feature wrapper.
func (s *Store) Sweep() error {
	if s == nil || s.db == nil {
		return nil
	}
	now := s.Now()
	var toDelete [][]byte

	if err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(entriesBucket)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var e Entry
			if err := json.Unmarshal(v, &e); err != nil {
				// Corrupt rows are also swept.
				cp := make([]byte, len(k))
				copy(cp, k)
				toDelete = append(toDelete, cp)
				return nil
			}
			if !e.BlockedUntil.After(now) {
				cp := make([]byte, len(k))
				copy(cp, k)
				toDelete = append(toDelete, cp)
			}
			return nil
		})
	}); err != nil {
		return err
	}

	if len(toDelete) == 0 {
		return nil
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(entriesBucket)
		if b == nil {
			return nil
		}
		for _, k := range toDelete {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}

// trimTenantLRU ensures no tenant has more than max entries. When the
// count exceeds the cap, entries with the lowest BlockedUntil are
// deleted — i.e. those closest to expiry, matching the spec's LRU
// semantics for "evict the entry that has been blocked longest".
func trimTenantLRU(b *bolt.Bucket, tenant string, max int) error {
	prefix := []byte(tenant + "\x00")

	type rec struct {
		key []byte
		at  time.Time
	}
	var all []rec
	c := b.Cursor()
	for k, v := c.Seek(prefix); k != nil && hasPrefix(k, prefix); k, v = c.Next() {
		var e Entry
		if err := json.Unmarshal(v, &e); err != nil {
			continue
		}
		cp := make([]byte, len(k))
		copy(cp, k)
		all = append(all, rec{key: cp, at: e.BlockedUntil})
	}
	if len(all) <= max {
		return nil
	}
	sort.Slice(all, func(i, j int) bool { return all[i].at.Before(all[j].at) })
	surplus := len(all) - max
	for i := 0; i < surplus; i++ {
		if err := b.Delete(all[i].key); err != nil {
			return err
		}
	}
	return nil
}

// hasPrefix returns true when b starts with prefix. Inlined to avoid
// importing bytes in a hot loop.
func hasPrefix(b, prefix []byte) bool {
	if len(b) < len(prefix) {
		return false
	}
	for i := range prefix {
		if b[i] != prefix[i] {
			return false
		}
	}
	return true
}
