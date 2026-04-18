package ttlblock

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// fakeClock is a deterministic clock useful for TTL assertions.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{t: t} }

func (fc *fakeClock) now() time.Time {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return fc.t
}

func (fc *fakeClock) advance(d time.Duration) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.t = fc.t.Add(d)
}

// newTestStore opens a Store rooted at t.TempDir() with the given
// saltFile filename (placed in the same dir when non-empty). A no-salt
// store is opened by passing "".
func newTestStore(t *testing.T, saltBase string) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "ttlblock.db")
	saltFile := ""
	if saltBase != "" {
		saltFile = filepath.Join(dir, saltBase)
	}
	s, err := OpenStore(dbPath, saltFile)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() {
		_ = s.Close()
	})
	return s, dbPath
}

func TestStore_AddContainsAndTTLExpiry(t *testing.T) {
	s, _ := newTestStore(t, "")

	base := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	clock := newFakeClock(base)
	s.SetClock(clock.now)

	if err := s.Add("tenant-a", "1.2.3.4", 10*time.Minute, "probe", 0); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !s.Contains("tenant-a", "1.2.3.4") {
		t.Fatalf("Contains=false immediately after Add")
	}
	if s.Contains("tenant-a", "9.9.9.9") {
		t.Fatalf("unrelated IP reported as blocked")
	}
	if s.Contains("tenant-b", "1.2.3.4") {
		t.Fatalf("tenant isolation broken: tenant-b sees tenant-a's entry")
	}

	// Advance to one second before expiry — still blocked.
	clock.advance(10*time.Minute - 1*time.Second)
	if !s.Contains("tenant-a", "1.2.3.4") {
		t.Fatalf("expired too early")
	}

	// Advance past expiry.
	clock.advance(2 * time.Second)
	if s.Contains("tenant-a", "1.2.3.4") {
		t.Fatalf("entry still live after TTL elapsed")
	}
}

func TestStore_RemoveWorks(t *testing.T) {
	s, _ := newTestStore(t, "")
	if err := s.Add("tenant-a", "1.2.3.4", time.Hour, "x", 0); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := s.Remove("tenant-a", "1.2.3.4"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if s.Contains("tenant-a", "1.2.3.4") {
		t.Fatalf("Contains still true after Remove")
	}
	// Removing a missing entry is not an error.
	if err := s.Remove("tenant-a", "1.2.3.4"); err != nil {
		t.Fatalf("second Remove: %v", err)
	}
}

func TestStore_SaltedHashesHidePlaintextIPs(t *testing.T) {
	s, dbPath := newTestStore(t, "salt")
	if !s.SaltedHashes() {
		t.Fatalf("expected salted hashes to be enabled when saltFile is provided")
	}
	ip := "203.0.113.77"
	if err := s.Add("tenant-a", ip, time.Hour, "secret-reason", 0); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Read the raw DB file and confirm the plaintext IP is absent.
	raw, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if bytes.Contains(raw, []byte(ip)) {
		t.Fatalf("plaintext IP %q leaked into DB file", ip)
	}
	// The reason *is* allowed to leak — it may even be operator-provided.
	if !bytes.Contains(raw, []byte("secret-reason")) {
		// Not a hard failure; just a sanity check that we looked at
		// the right bytes.
		t.Logf("reason not found in DB file; test may be stale")
	}
}

func TestStore_ReopenPreservesNonExpiredEntries(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "ttlblock.db")

	s, err := OpenStore(dbPath, "")
	if err != nil {
		t.Fatalf("OpenStore 1: %v", err)
	}
	base := time.Date(2026, 4, 18, 9, 0, 0, 0, time.UTC)
	clock := newFakeClock(base)
	s.SetClock(clock.now)

	if err := s.Add("tenant-a", "1.1.1.1", time.Hour, "keep", 0); err != nil {
		t.Fatalf("Add fresh: %v", err)
	}
	if err := s.Add("tenant-a", "2.2.2.2", time.Nanosecond, "expire", 0); err != nil {
		t.Fatalf("Add expiring: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopen with a clock advanced past the second entry's expiry.
	s2, err := OpenStore(dbPath, "")
	if err != nil {
		t.Fatalf("OpenStore 2: %v", err)
	}
	defer s2.Close()
	clock.advance(5 * time.Minute)
	s2.SetClock(clock.now)

	if !s2.Contains("tenant-a", "1.1.1.1") {
		t.Fatalf("fresh entry lost across reopen")
	}
	if s2.Contains("tenant-a", "2.2.2.2") {
		t.Fatalf("expired entry still live across reopen")
	}
}

func TestStore_SweepRemovesExpiredKeepsFresh(t *testing.T) {
	s, _ := newTestStore(t, "")
	clock := newFakeClock(time.Date(2026, 4, 18, 0, 0, 0, 0, time.UTC))
	s.SetClock(clock.now)

	if err := s.Add("t", "1.1.1.1", 10*time.Minute, "fresh", 0); err != nil {
		t.Fatalf("Add fresh: %v", err)
	}
	if err := s.Add("t", "2.2.2.2", 1*time.Second, "short", 0); err != nil {
		t.Fatalf("Add short: %v", err)
	}
	if err := s.Add("t", "3.3.3.3", 10*time.Minute, "fresh2", 0); err != nil {
		t.Fatalf("Add fresh2: %v", err)
	}

	clock.advance(5 * time.Second)
	if err := s.Sweep(); err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	if s.Contains("t", "2.2.2.2") {
		t.Fatalf("expired entry survived Sweep")
	}
	if !s.Contains("t", "1.1.1.1") || !s.Contains("t", "3.3.3.3") {
		t.Fatalf("fresh entries deleted by Sweep")
	}

	list := s.List("t")
	if len(list) != 2 {
		t.Fatalf("List after Sweep = %d entries, want 2", len(list))
	}
	for _, e := range list {
		if e.IPOrHash == "" {
			t.Fatalf("entry missing IPOrHash: %+v", e)
		}
	}
}

func TestStore_ListSortedByBlockedUntil(t *testing.T) {
	s, _ := newTestStore(t, "")
	clock := newFakeClock(time.Date(2026, 4, 18, 0, 0, 0, 0, time.UTC))
	s.SetClock(clock.now)

	// Add in reverse TTL order.
	_ = s.Add("t", "a.1", 3*time.Hour, "", 0)
	_ = s.Add("t", "b.2", 1*time.Hour, "", 0)
	_ = s.Add("t", "c.3", 2*time.Hour, "", 0)

	got := s.List("t")
	if len(got) != 3 {
		t.Fatalf("List len = %d, want 3", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].BlockedUntil.After(got[i].BlockedUntil) {
			t.Fatalf("List not sorted ascending at index %d: %v > %v",
				i-1, got[i-1].BlockedUntil, got[i].BlockedUntil)
		}
	}
}

func TestStore_MaxEntriesEvictsLRU(t *testing.T) {
	s, _ := newTestStore(t, "")
	clock := newFakeClock(time.Date(2026, 4, 18, 0, 0, 0, 0, time.UTC))
	s.SetClock(clock.now)

	// Three entries with distinct TTLs so we can reason about which one gets
	// trimmed.
	_ = s.Add("t", "oldest", 10*time.Minute, "", 0)
	clock.advance(time.Second)
	_ = s.Add("t", "middle", 20*time.Minute, "", 0)
	clock.advance(time.Second)
	_ = s.Add("t", "newest", 30*time.Minute, "", 0)

	// Insert a fourth with max=3: oldest must be evicted.
	clock.advance(time.Second)
	if err := s.Add("t", "fresh", time.Hour, "", 3); err != nil {
		t.Fatalf("Add with LRU trim: %v", err)
	}

	list := s.List("t")
	names := map[string]bool{}
	for _, e := range list {
		names[e.IPOrHash] = true
	}
	if names["oldest"] {
		t.Fatalf("oldest entry should have been evicted, got %v", names)
	}
	if !names["fresh"] {
		t.Fatalf("newly added entry missing, got %v", names)
	}
	if len(list) != 3 {
		t.Fatalf("expected 3 entries after LRU trim, got %d", len(list))
	}
}

func TestStore_AddRejectsZeroTTL(t *testing.T) {
	s, _ := newTestStore(t, "")
	if err := s.Add("t", "1.1.1.1", 0, "", 0); err == nil {
		t.Fatalf("expected zero-ttl Add to fail")
	}
	if err := s.Add("t", "1.1.1.1", -time.Second, "", 0); err == nil {
		t.Fatalf("expected negative-ttl Add to fail")
	}
}

func TestStore_AddRejectsEmptyTenantOrIP(t *testing.T) {
	s, _ := newTestStore(t, "")
	if err := s.Add("", "1.1.1.1", time.Hour, "", 0); err == nil {
		t.Fatalf("empty tenant should fail")
	}
	if err := s.Add("t", "", time.Hour, "", 0); err == nil {
		t.Fatalf("empty ip should fail")
	}
}

func TestStore_ConcurrentAddAndContains(t *testing.T) {
	s, _ := newTestStore(t, "salt")

	const workers = 16
	const ops = 200
	var wg sync.WaitGroup
	var contained atomic.Int64

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < ops; i++ {
				tenant := "t"
				ip := randomIPForTest(id, i)
				if err := s.Add(tenant, ip, time.Hour, "r", 0); err != nil {
					t.Errorf("Add: %v", err)
					return
				}
				if s.Contains(tenant, ip) {
					contained.Add(1)
				}
			}
		}(w)
	}
	wg.Wait()

	if contained.Load() == 0 {
		t.Fatalf("no concurrent writes were observed by Contains")
	}
}

// randomIPForTest fabricates a unique-ish IPv4 for worker+iter.
func randomIPForTest(worker, iter int) string {
	return "10." + itoa(worker&0xff) + "." + itoa((iter>>8)&0xff) + "." + itoa(iter&0xff)
}

func itoa(n int) string {
	// Local version to avoid pulling strconv into the hot-loop suite;
	// the value is always 0..255.
	if n == 0 {
		return "0"
	}
	var buf [4]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + (n % 10))
		n /= 10
	}
	return string(buf[i:])
}

func TestStore_SaltPersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "db")
	saltPath := filepath.Join(dir, "salt")

	s1, err := OpenStore(dbPath, saltPath)
	if err != nil {
		t.Fatalf("OpenStore 1: %v", err)
	}
	if err := s1.Add("t", "1.2.3.4", time.Hour, "", 0); err != nil {
		t.Fatalf("Add: %v", err)
	}
	_ = s1.Close()

	// Delete the salt file; the "meta" bucket must recreate it.
	_ = os.Remove(saltPath)

	s2, err := OpenStore(dbPath, saltPath)
	if err != nil {
		t.Fatalf("OpenStore 2: %v", err)
	}
	defer s2.Close()

	if !s2.Contains("t", "1.2.3.4") {
		t.Fatalf("entry lost after salt-file deletion; salt not round-tripped via meta bucket")
	}
	// And the salt file should be back.
	if _, err := os.Stat(saltPath); err != nil {
		t.Fatalf("salt file not regenerated: %v", err)
	}
}

func TestStore_SaltEncodedAsHexOnDisk(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "db")
	saltPath := filepath.Join(dir, "salt")

	s, err := OpenStore(dbPath, saltPath)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer s.Close()

	raw, err := os.ReadFile(saltPath)
	if err != nil {
		t.Fatalf("ReadFile salt: %v", err)
	}
	if len(raw) != 2*saltLen {
		t.Fatalf("salt file length = %d, want %d (hex encoding)", len(raw), 2*saltLen)
	}
	if _, err := hex.DecodeString(string(raw)); err != nil {
		t.Fatalf("salt file is not valid hex: %v", err)
	}
}

func TestStore_CorruptRowIsSwept(t *testing.T) {
	s, dbPath := newTestStore(t, "")
	if err := s.Add("t", "1.1.1.1", time.Hour, "ok", 0); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Poke a garbage row directly via bbolt.
	db, err := bolt.Open(dbPath, 0o600, &bolt.Options{Timeout: 2 * time.Second, ReadOnly: false})
	if err != nil {
		// bbolt does not allow two concurrent writers on the same file,
		// so we close our store first.
		_ = s.Close()
		db, err = bolt.Open(dbPath, 0o600, &bolt.Options{Timeout: 2 * time.Second})
		if err != nil {
			t.Fatalf("bolt.Open corrupt: %v", err)
		}
	} else {
		// Unexpected: two writers coexisted. Close both.
		_ = s.Close()
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(entriesBucket)
		if b == nil {
			return errors.New("missing bucket")
		}
		return b.Put([]byte("t\x00garbage"), []byte("not-json"))
	}); err != nil {
		t.Fatalf("poke garbage: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close corrupt handle: %v", err)
	}

	// Reopen, Sweep, and confirm the bad row is gone while the good one stays.
	s2, err := OpenStore(dbPath, "")
	if err != nil {
		t.Fatalf("OpenStore after poking: %v", err)
	}
	defer s2.Close()
	if err := s2.Sweep(); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if !s2.Contains("t", "1.1.1.1") {
		t.Fatalf("valid entry lost after sweeping garbage row")
	}
	// Spot-check directly that the garbage row is absent.
	_ = s2.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(entriesBucket)
		if b == nil {
			return nil
		}
		if v := b.Get([]byte("t\x00garbage")); v != nil {
			t.Fatalf("garbage row survived Sweep: %q", v)
		}
		return nil
	})
}

func TestStore_EntryJSONRoundTrip(t *testing.T) {
	e := Entry{
		Tenant:       "t",
		IPOrHash:     "abc",
		BlockedUntil: time.Date(2026, 4, 18, 13, 14, 15, 0, time.UTC),
		Reason:       "hi",
	}
	buf, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var back Entry
	if err := json.Unmarshal(buf, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back != e {
		t.Fatalf("round-trip mismatch: %+v vs %+v", back, e)
	}
}

func TestStore_ClosedOrNilNoOp(t *testing.T) {
	var s *Store
	if err := s.Close(); err != nil {
		t.Fatalf("nil Close: %v", err)
	}
	if s.Contains("t", "1.1.1.1") {
		t.Fatalf("nil Contains should be false")
	}
	if err := s.Sweep(); err != nil {
		t.Fatalf("nil Sweep: %v", err)
	}
}

// ensure the io.Closer contract is satisfied (helps when wiring into
// defer-close helpers elsewhere in the codebase).
var _ io.Closer = (*Store)(nil)
