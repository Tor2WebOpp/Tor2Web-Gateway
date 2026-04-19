package hub

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"

	"gateway/internal/config"
)

const (
	// globalsFile is the singleton globals.yaml under the data dir.
	globalsFile = "globals.yaml"
	// tenantsDir holds one <host>.yaml per tenant.
	tenantsDir = "tenants"
	// tenantExt is the file extension used for tenant YAML files.
	tenantExt = ".yaml"
	// watchDebounce collapses fsnotify event storms (editor saves emit
	// create+write+rename in rapid succession) into a single reload.
	watchDebounce = 300 * time.Millisecond
)

// Storage is the file-backed persistence layer for the tenant registry. All
// writes are atomic (write to tmp in the same dir, fsync, rename). Reads
// ignore files whose names do not end in .yaml or contain directory
// separators.
type Storage struct {
	dataDir    string
	tenantsDir string
}

// NewStorage returns a Storage rooted at dataDir. dataDir is created (with
// 0755) if it does not exist, and a tenants/ subdirectory is ensured.
func NewStorage(dataDir string) (*Storage, error) {
	if dataDir == "" {
		return nil, errors.New("hub storage: data_dir is required")
	}
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, fmt.Errorf("hub storage: abs %q: %w", dataDir, err)
	}
	td := filepath.Join(abs, tenantsDir)
	if err := os.MkdirAll(td, 0o755); err != nil {
		return nil, fmt.Errorf("hub storage: mkdir tenants dir: %w", err)
	}
	return &Storage{dataDir: abs, tenantsDir: td}, nil
}

// DataDir returns the absolute directory backing this Storage.
func (s *Storage) DataDir() string { return s.dataDir }

// TenantsDir returns the absolute path to the tenants/ subdirectory.
func (s *Storage) TenantsDir() string { return s.tenantsDir }

// GlobalsPath returns the absolute path to globals.yaml.
func (s *Storage) GlobalsPath() string { return filepath.Join(s.dataDir, globalsFile) }

// TenantPath returns the absolute path to a tenant YAML file.
func (s *Storage) TenantPath(host string) string {
	return filepath.Join(s.tenantsDir, sanitizeHost(host)+tenantExt)
}

// WriteTenant persists one tenant file atomically: marshal, write tmp, rename.
// An empty host is rejected; t.Host is normalised to the sanitised filename
// stem before serialisation so reloads see a consistent value.
func (s *Storage) WriteTenant(host string, t config.TenantConf) error {
	if host == "" {
		return errors.New("hub storage: host is required")
	}
	t.Host = host
	data, err := yaml.Marshal(&t)
	if err != nil {
		return fmt.Errorf("hub storage: marshal tenant %q: %w", host, err)
	}
	return atomicWrite(s.TenantPath(host), data)
}

// DeleteTenantFile removes a tenant file; missing file is not an error.
func (s *Storage) DeleteTenantFile(host string) error {
	p := s.TenantPath(host)
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("hub storage: remove %q: %w", p, err)
	}
	return nil
}

// WriteGlobals persists globals.yaml atomically.
func (s *Storage) WriteGlobals(g config.GlobalsConf) error {
	data, err := yaml.Marshal(&g)
	if err != nil {
		return fmt.Errorf("hub storage: marshal globals: %w", err)
	}
	return atomicWrite(s.GlobalsPath(), data)
}

// LoadAll reads globals.yaml (if present) and every *.yaml file under
// tenants/. A missing globals file is not an error — it yields the zero
// GlobalsConf. Individual tenant parse errors are returned as a joined
// error so callers see every malformed file at once.
func (s *Storage) LoadAll() (config.GlobalsConf, map[string]config.TenantConf, error) {
	tenants := make(map[string]config.TenantConf)

	var globals config.GlobalsConf
	if _, err := os.Stat(s.GlobalsPath()); err == nil {
		g, err := config.LoadGlobalsFile(s.GlobalsPath())
		if err != nil {
			return config.GlobalsConf{}, nil, err
		}
		globals = *g
	} else if !errors.Is(err, os.ErrNotExist) {
		return config.GlobalsConf{}, nil, fmt.Errorf("hub storage: stat globals: %w", err)
	}

	entries, err := os.ReadDir(s.tenantsDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return globals, tenants, nil
		}
		return config.GlobalsConf{}, nil, fmt.Errorf("hub storage: readdir tenants: %w", err)
	}

	var errs []error
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), tenantExt) {
			continue
		}
		full := filepath.Join(s.tenantsDir, e.Name())
		tc, err := config.LoadTenantFile(full)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		tenants[tc.Host] = *tc
	}
	if len(errs) > 0 {
		return globals, tenants, errors.Join(errs...)
	}
	return globals, tenants, nil
}

// Watch blocks until ctx is cancelled, forwarding every file event affecting
// globals.yaml or any *.yaml under tenants/ to onChange. Events are debounced
// by watchDebounce so a burst (editor save + rename) triggers one call.
//
// Errors from fsnotify are dropped intentionally; the watcher is best-effort
// and the registry never relies on it for correctness (writes go through
// Storage's mutative methods which update state directly).
func (s *Storage) Watch(ctx context.Context, onChange func()) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("hub storage: fsnotify new: %w", err)
	}
	if err := w.Add(s.dataDir); err != nil {
		_ = w.Close()
		return fmt.Errorf("hub storage: watch data dir: %w", err)
	}
	if err := w.Add(s.tenantsDir); err != nil {
		_ = w.Close()
		return fmt.Errorf("hub storage: watch tenants dir: %w", err)
	}

	go func() {
		defer w.Close()
		var (
			timer *time.Timer
			cbMu  sync.Mutex
		)
		for {
			select {
			case <-ctx.Done():
				if timer != nil {
					timer.Stop()
				}
				return
			case ev, ok := <-w.Events:
				if !ok {
					return
				}
				if !s.relevantEvent(ev) {
					continue
				}
				// Serialize the debounced callback so an event arriving
				// right as the previous invocation is still running does
				// not reenter it: AfterFunc fires on its own goroutine, and
				// Reset() mid-execution schedules another concurrent
				// fire that would read/broadcast an inconsistent snapshot.
				if timer == nil {
					timer = time.AfterFunc(watchDebounce, func() {
						cbMu.Lock()
						defer cbMu.Unlock()
						onChange()
					})
				} else {
					timer.Stop()
					timer.Reset(watchDebounce)
				}
			case _, ok := <-w.Errors:
				if !ok {
					return
				}
				// Errors are advisory; keep watching.
			}
		}
	}()

	return nil
}

// relevantEvent decides whether an fsnotify event should schedule a reload.
// Only *.yaml under dataDir (globals) or tenantsDir is considered; tmp files
// used by atomic writes are ignored.
func (s *Storage) relevantEvent(ev fsnotify.Event) bool {
	base := filepath.Base(ev.Name)
	if strings.HasPrefix(base, ".tmp-") {
		return false
	}
	if !strings.HasSuffix(strings.ToLower(base), tenantExt) {
		return false
	}
	return true
}

// atomicWrite writes data to a tmp file in path's directory and renames it
// over path. On Windows, rename over an existing file replaces it.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("hub storage: mkdir %q: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, ".tmp-*"+filepath.Ext(path))
	if err != nil {
		return fmt.Errorf("hub storage: tempfile: %w", err)
	}
	tmp := f.Name()
	cleanup := func() { _ = os.Remove(tmp) }
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		cleanup()
		return fmt.Errorf("hub storage: write %q: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		cleanup()
		return fmt.Errorf("hub storage: fsync %q: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return fmt.Errorf("hub storage: close %q: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		cleanup()
		return fmt.Errorf("hub storage: rename %q -> %q: %w", tmp, path, err)
	}
	return nil
}

// sanitizeHost collapses characters unsafe in filenames (path separators,
// drive colons on Windows) into dashes. The canonical host is preserved
// inside the YAML body via TenantConf.Host; the filename is only a lookup
// key, not a source of truth.
func sanitizeHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	var b strings.Builder
	b.Grow(len(h))
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '.' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return b.String()
}
