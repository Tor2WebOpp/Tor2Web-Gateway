package abuse

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry is the persisted record for a single abuse report. It never
// contains the raw client IP; ClientIPHash is a sha256 digest of the
// originating IP salted with the per-process salt.
type Entry struct {
	Timestamp    time.Time `json:"timestamp"`
	Tenant       string    `json:"tenant"`
	ClientIPHash string    `json:"client_ip_hash"`
	Onion        string    `json:"onion"`
	Reason       string    `json:"reason"`
	Contact      string    `json:"contact,omitempty"`
	Details      string    `json:"details,omitempty"`
}

// Store is an append-only JSONL log. A single file descriptor is kept
// open for the lifetime of the Store; Append serialises writes under
// mu so concurrent callers produce well-formed, line-separated JSON.
type Store struct {
	path string

	mu sync.Mutex
	f  *os.File
}

// OpenStore opens (or creates) path in append-only mode with file mode
// 0600. Parent directories are created as needed, also with 0700.
func OpenStore(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("abuse: store path is empty")
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("abuse: mkdir %q: %w", dir, err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("abuse: open %q: %w", path, err)
	}
	// Ensure mode even on pre-existing files.
	_ = os.Chmod(path, 0o600)
	return &Store{path: path, f: f}, nil
}

// Path returns the backing file path.
func (s *Store) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Append serialises entry as one JSON object followed by a newline and
// writes it to the log. The write is flushed to the OS buffer but not
// synced to disk; callers that want a crash-consistent guarantee can
// use Sync explicitly.
func (s *Store) Append(entry Entry) error {
	if s == nil || s.f == nil {
		return errors.New("abuse: store is not open")
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	} else {
		entry.Timestamp = entry.Timestamp.UTC()
	}
	buf, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("abuse: marshal entry: %w", err)
	}
	buf = append(buf, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.f.Write(buf); err != nil {
		return fmt.Errorf("abuse: write entry: %w", err)
	}
	return nil
}

// Sync flushes pending writes to disk.
func (s *Store) Sync() error {
	if s == nil || s.f == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Sync()
}

// Close flushes and closes the backing file. Further calls to Append
// return an error. Close is idempotent.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}
