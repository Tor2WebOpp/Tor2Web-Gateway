package hub

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"gateway/internal/config"
)

func TestNewStorage_CreatesTenantsDir(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "hub")
	st, err := NewStorage(sub)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	if _, err := os.Stat(st.TenantsDir()); err != nil {
		t.Fatalf("tenants dir not created: %v", err)
	}
}

func TestNewStorage_EmptyDir(t *testing.T) {
	if _, err := NewStorage(""); err == nil {
		t.Fatal("expected error for empty data_dir")
	}
}

func sampleTenant(host string) config.TenantConf {
	return config.TenantConf{
		Host:    host,
		Enabled: true,
		Backends: []config.BackendConf{
			{Addr: host + "-backendd.onion", Weight: 1},
		},
	}
}

func TestStorage_WriteTenant_LoadAll_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStorage(dir)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	if err := st.WriteTenant("example.tld", sampleTenant("example.tld")); err != nil {
		t.Fatalf("WriteTenant: %v", err)
	}
	_, tenants, err := st.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if _, ok := tenants["example.tld"]; !ok {
		t.Fatalf("tenant example.tld missing from LoadAll result: %+v", tenants)
	}
}

func TestStorage_DeleteTenantFile(t *testing.T) {
	dir := t.TempDir()
	st, _ := NewStorage(dir)
	if err := st.WriteTenant("a.tld", sampleTenant("a.tld")); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteTenantFile("a.tld"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(st.TenantPath("a.tld")); !os.IsNotExist(err) {
		t.Fatalf("file still present: err=%v", err)
	}
	// Deleting twice is not an error.
	if err := st.DeleteTenantFile("a.tld"); err != nil {
		t.Fatalf("second delete: %v", err)
	}
}

func TestStorage_WriteGlobals_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	st, _ := NewStorage(dir)
	g := config.GlobalsConf{
		BlockResponse: config.BlockResponseConf{Default: config.BlockDrop},
	}
	if err := st.WriteGlobals(g); err != nil {
		t.Fatalf("WriteGlobals: %v", err)
	}
	got, _, err := st.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if got.BlockResponse.Default != config.BlockDrop {
		t.Fatalf("BlockResponse.Default = %q", got.BlockResponse.Default)
	}
}

func TestStorage_AtomicWrite_NoTmpLeftover(t *testing.T) {
	dir := t.TempDir()
	st, _ := NewStorage(dir)
	if err := st.WriteTenant("x.tld", sampleTenant("x.tld")); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(st.TenantsDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".yaml" {
			t.Fatalf("unexpected leftover file %q", e.Name())
		}
	}
}

func TestStorage_LoadAll_NoGlobals(t *testing.T) {
	dir := t.TempDir()
	st, _ := NewStorage(dir)
	// No files anywhere.
	g, tenants, err := st.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(tenants) != 0 {
		t.Fatalf("expected zero tenants, got %d", len(tenants))
	}
	if g.BlockResponse.Default != "" {
		t.Fatalf("expected empty globals, got %+v", g)
	}
}

func TestStorage_Watch_TriggersOnChange(t *testing.T) {
	dir := t.TempDir()
	st, _ := NewStorage(dir)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var calls atomic.Int32
	if err := st.Watch(ctx, func() { calls.Add(1) }); err != nil {
		t.Fatalf("Watch: %v", err)
	}

	// Small delay for watcher startup on slower platforms.
	time.Sleep(50 * time.Millisecond)

	if err := st.WriteTenant("w.tld", sampleTenant("w.tld")); err != nil {
		t.Fatal(err)
	}

	// Debounce is 300ms; allow up to 1.5s for the callback.
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if calls.Load() >= 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("watcher did not fire; calls=%d", calls.Load())
}

func TestStorage_SanitizeHost(t *testing.T) {
	// The helper must be deterministic and collapse path-unsafe runes.
	got := sanitizeHost("Example/With:Evil\\Bytes")
	// All uppercase should be lowered, and separators replaced.
	for _, r := range got {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
			continue
		default:
			t.Fatalf("unexpected rune %q in sanitised host %q", r, got)
		}
	}
}
