package admin

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

// auditBucket holds one row per audit event keyed by the 8-byte
// big-endian nano timestamp. The value is the JSONL line as written
// to disk, allowing Query to load events without re-parsing the file.
var auditBucket = []byte("events")

// Event is the on-disk record for a single admin action. The Diff
// payload is opaque to the audit subsystem — callers are responsible
// for hashing any sensitive data (raw IPs, hostnames) before writing.
type Event struct {
	Time      time.Time      `json:"ts"`
	Actor     string         `json:"actor"`
	ActorIP   string         `json:"actor_ip_hash"`
	NodeID    string         `json:"node_id"`
	Action    string         `json:"action"`
	Target    string         `json:"target"`
	Diff      map[string]any `json:"diff,omitempty"`
	SessionID string         `json:"session_id,omitempty"`
}

// RawLeakChecker is an optional callback supplied to OpenLog. When
// non-nil, Log.Write invokes it with the marshaled JSON payload of
// the event; if the callback returns a non-nil error, the write is
// rejected before any file or index mutation occurs. The check
// exists to defend against accidental raw-PII leakage in audit Diff
// payloads — implementations typically scan the payload for any
// substring that should never appear (raw IP, raw hostname).
type RawLeakChecker func(payload []byte) error

// Log appends events to a daily JSONL file under <dataDir>/audit/ and
// indexes them by nanosecond timestamp in a BoltDB next to it.
//
// Safe for concurrent Write/Query. Close is idempotent.
type Log struct {
	dataDir string
	dir     string // <dataDir>/audit
	indexDB *bolt.DB
	leakCk  RawLeakChecker

	mu     sync.Mutex
	curDay string   // YYYY-MM-DD of the currently-open file
	curF   *os.File // append-mode handle, nil between days
	closed bool
}

// OpenLog creates the audit/ directory under dataDir (mode 0700) and
// opens the BoltDB index. Subsequent Write calls open the daily JSONL
// file lazily on first use.
func OpenLog(dataDir string) (*Log, error) {
	return OpenLogWithChecker(dataDir, nil)
}

// OpenLogWithChecker is OpenLog with an optional RawLeakChecker
// installed. The checker is invoked synchronously inside Write before
// any file or index mutation; an error from the checker is returned
// to the caller verbatim.
func OpenLogWithChecker(dataDir string, leakCk RawLeakChecker) (*Log, error) {
	if dataDir == "" {
		return nil, errors.New("admin: dataDir is required")
	}
	dir := filepath.Join(dataDir, "audit")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("admin: mkdir audit dir: %w", err)
	}
	dbPath := filepath.Join(dir, "audit.bolt")
	db, err := bolt.Open(dbPath, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("admin: open audit bolt: %w", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists(auditBucket)
		return e
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("admin: init audit bucket: %w", err)
	}
	return &Log{
		dataDir: dataDir,
		dir:     dir,
		indexDB: db,
		leakCk:  leakCk,
	}, nil
}

// Write appends e to the current day's JSONL file and indexes it in
// the BoltDB. The Time field is replaced with time.Now if zero so
// callers do not need to set it explicitly. Concurrent Writers are
// serialized through l.mu — both file append and bolt index update
// are wrapped under the same lock so on-disk and in-index ordering
// remain consistent.
func (l *Log) Write(e Event) error {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	payload, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("admin: marshal audit event: %w", err)
	}
	if l.leakCk != nil {
		if err := l.leakCk(payload); err != nil {
			return err
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return errors.New("admin: audit log is closed")
	}

	if err := l.ensureDayFileLocked(e.Time); err != nil {
		return err
	}
	// JSONL — one event per line.
	if _, err := l.curF.Write(payload); err != nil {
		return fmt.Errorf("admin: write audit line: %w", err)
	}
	if _, err := l.curF.Write([]byte{'\n'}); err != nil {
		return fmt.Errorf("admin: write audit newline: %w", err)
	}
	if err := l.curF.Sync(); err != nil {
		return fmt.Errorf("admin: fsync audit: %w", err)
	}

	// Index by nanosecond timestamp. Collisions on the same nanosecond
	// are rare but possible; in that case we tag the key with a 2-byte
	// sequence suffix so the bolt key remains unique without losing
	// the natural sort order.
	key := nanoKey(e.Time)
	return l.indexDB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(auditBucket)
		if b == nil {
			return errors.New("admin: audit bucket missing")
		}
		k := key
		var seq uint16
		for b.Get(k) != nil {
			seq++
			if seq == 0 {
				return errors.New("admin: audit index key exhausted")
			}
			k = appendSeq(key, seq)
		}
		return b.Put(k, payload)
	})
}

// Query returns up to limit events with timestamps strictly after
// since, ordered ascending. A non-positive limit is treated as
// unbounded. The events are reconstructed from the bolt index, which
// stores the JSONL payload alongside each key — the daily file is
// not re-read.
func (l *Log) Query(since time.Time, limit int) ([]Event, error) {
	out := make([]Event, 0)
	startKey := nanoKey(since)
	if err := l.indexDB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(auditBucket)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		k, v := c.Seek(startKey)
		// Skip exact matches on the boundary — Query returns events
		// strictly newer than since, matching the API contract for
		// /api/audit?since=…
		for k != nil && keyAtOrBefore(k, since) {
			k, v = c.Next()
		}
		for ; k != nil; k, v = c.Next() {
			var e Event
			if err := json.Unmarshal(v, &e); err != nil {
				continue
			}
			out = append(out, e)
			if limit > 0 && len(out) >= limit {
				return nil
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// Close flushes the current file and closes the index. Idempotent —
// subsequent calls are no-ops and return nil.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	var ferr, derr error
	if l.curF != nil {
		ferr = l.curF.Close()
		l.curF = nil
	}
	if l.indexDB != nil {
		derr = l.indexDB.Close()
		l.indexDB = nil
	}
	if ferr != nil {
		return ferr
	}
	return derr
}

// ensureDayFileLocked rotates the JSONL handle when the date rolls
// over. Caller must hold l.mu.
func (l *Log) ensureDayFileLocked(t time.Time) error {
	day := t.UTC().Format("2006-01-02")
	if l.curF != nil && l.curDay == day {
		return nil
	}
	if l.curF != nil {
		_ = l.curF.Close()
		l.curF = nil
	}
	path := filepath.Join(l.dir, day+".jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("admin: open audit file: %w", err)
	}
	l.curF = f
	l.curDay = day
	return nil
}

// nanoKey encodes a time as an 8-byte big-endian unix-nano key,
// suitable for byte-ordered bolt cursors.
func nanoKey(t time.Time) []byte {
	k := make([]byte, 8)
	// Clamp negatives to zero so pre-epoch times sort below all real
	// events rather than overflowing.
	n := t.UnixNano()
	if n < 0 {
		n = 0
	}
	binary.BigEndian.PutUint64(k, uint64(n))
	return k
}

// appendSeq tags a base nano key with a 2-byte sequence suffix used
// only when two events share an exact nanosecond.
func appendSeq(base []byte, seq uint16) []byte {
	out := make([]byte, len(base)+2)
	copy(out, base)
	binary.BigEndian.PutUint16(out[len(base):], seq)
	return out
}

// keyAtOrBefore returns true when the key represents a timestamp at
// or before the supplied time. Used to enforce strict-after Query
// semantics regardless of nanosecond collisions.
func keyAtOrBefore(k []byte, t time.Time) bool {
	if len(k) < 8 {
		return true
	}
	got := int64(binary.BigEndian.Uint64(k[:8]))
	return got <= t.UnixNano()
}

// readJSONL is a helper used by tests and external tooling. It scans
// the supplied file path and returns each successfully-parsed Event
// in order. Malformed lines are skipped silently.
func readJSONL(path string) ([]Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Event
	sc := bufio.NewScanner(f)
	// Audit lines may grow with large diffs; raise the per-line cap.
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		out = append(out, e)
	}
	return out, sc.Err()
}
