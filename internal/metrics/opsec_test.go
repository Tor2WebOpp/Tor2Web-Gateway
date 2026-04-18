package metrics

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func mustLabeler(t *testing.T, cfg Config) *Labeler {
	t.Helper()
	l, err := NewLabeler(cfg)
	if err != nil {
		t.Fatalf("NewLabeler: %v", err)
	}
	return l
}

func tempSaltPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "salt")
}

func TestTenantDeterministicWithinProcess(t *testing.T) {
	l := mustLabeler(t, Config{HashTenantLabels: true, SaltFile: tempSaltPath(t)})
	got1 := l.Tenant("example.tld")
	got2 := l.Tenant("example.tld")
	if got1 != got2 {
		t.Fatalf("Tenant not deterministic: %q vs %q", got1, got2)
	}
	// Two different hosts must differ.
	if l.Tenant("a.tld") == l.Tenant("b.tld") {
		t.Fatalf("distinct hosts hashed to same value")
	}
}

func TestTenantDiffersAcrossSalts(t *testing.T) {
	p1 := tempSaltPath(t)
	p2 := tempSaltPath(t)
	l1 := mustLabeler(t, Config{HashTenantLabels: true, SaltFile: p1})
	l2 := mustLabeler(t, Config{HashTenantLabels: true, SaltFile: p2})

	host := "example.tld"
	if l1.Tenant(host) == l2.Tenant(host) {
		t.Fatalf("tenant label collided across distinct salts")
	}
	// Sanity: the underlying salts themselves differ.
	s1, s2 := l1.Salt(), l2.Salt()
	if string(s1) == string(s2) {
		t.Fatalf("two freshly generated salts were identical")
	}
}

func TestTenantEmptyHost(t *testing.T) {
	cases := []Config{
		{HashTenantLabels: true, SaltFile: tempSaltPath(t)},
		{HashTenantLabels: false, SaltFile: tempSaltPath(t)},
	}
	for _, cfg := range cases {
		l := mustLabeler(t, cfg)
		if got := l.Tenant(""); got != TenantNone {
			t.Fatalf("Tenant(\"\") = %q, want %q (cfg=%+v)", got, TenantNone, cfg)
		}
	}
}

func TestTenantPassthroughWhenHashingDisabled(t *testing.T) {
	l := mustLabeler(t, Config{HashTenantLabels: false, SaltFile: tempSaltPath(t)})
	host := "example.tld"
	if got := l.Tenant(host); got != host {
		t.Fatalf("passthrough mode: Tenant(%q) = %q", host, got)
	}
}

func TestSaltFileCreatedWith0600(t *testing.T) {
	path := tempSaltPath(t)
	_, err := NewLabeler(Config{HashTenantLabels: true, SaltFile: path})
	if err != nil {
		t.Fatalf("NewLabeler: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat salt: %v", err)
	}
	if info.Size() != saltLen {
		t.Fatalf("salt size = %d, want %d", info.Size(), saltLen)
	}
	if runtime.GOOS != "windows" {
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Fatalf("salt mode = %#o, want 0600", mode)
		}
	}
}

func TestSaltFileRejectsLoosePerms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission check not applicable on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "loose-salt")
	// Write a non-empty salt with world-readable perms.
	data := make([]byte, saltLen)
	for i := range data {
		data[i] = byte(i)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	// Enforce mode even if umask masked the above.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	_, err := NewLabeler(Config{HashTenantLabels: true, SaltFile: path})
	if err == nil {
		t.Fatalf("expected error for loose perms, got nil")
	}
	if !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("error = %v, want mention of permissions", err)
	}
}

func TestTenantHashFormat(t *testing.T) {
	l := mustLabeler(t, Config{HashTenantLabels: true, SaltFile: tempSaltPath(t)})
	got := l.Tenant("example.tld")
	if !strings.HasPrefix(got, tenantPrefix) {
		t.Fatalf("missing prefix: %q", got)
	}
	hashPart := strings.TrimPrefix(got, tenantPrefix)
	if len(hashPart) != tenantHashHex {
		t.Fatalf("hash length = %d, want %d", len(hashPart), tenantHashHex)
	}
	if _, err := hex.DecodeString(hashPart); err != nil {
		t.Fatalf("hash is not valid hex: %v (%q)", err, hashPart)
	}
}

func TestClientIPHashFormat(t *testing.T) {
	l := mustLabeler(t, Config{HashTenantLabels: false, SaltFile: tempSaltPath(t)})
	got := l.ClientIP("192.0.2.1")
	if len(got) != clientIPHashHex {
		t.Fatalf("client IP length = %d, want %d", len(got), clientIPHashHex)
	}
	if _, err := hex.DecodeString(got); err != nil {
		t.Fatalf("client IP hash not hex: %v", err)
	}
	// Different IPs hash to different values.
	if l.ClientIP("192.0.2.1") == l.ClientIP("192.0.2.2") {
		t.Fatalf("distinct IPs hashed to same value")
	}
	// Empty IP yields empty label.
	if got := l.ClientIP(""); got != "" {
		t.Fatalf("ClientIP(\"\") = %q, want empty", got)
	}
}

func TestClientIPHashedEvenWhenTenantHashingDisabled(t *testing.T) {
	// When tenant hashing is off, client IPs still MUST be hashed.
	l := mustLabeler(t, Config{HashTenantLabels: false, SaltFile: tempSaltPath(t)})
	raw := "203.0.113.9"
	got := l.ClientIP(raw)
	if got == raw {
		t.Fatalf("client IP returned raw: %q", got)
	}
	if strings.Contains(got, ".") {
		t.Fatalf("client IP still looks like an IP: %q", got)
	}
}

func TestSaltCopyIsDefensive(t *testing.T) {
	l := mustLabeler(t, Config{HashTenantLabels: true, SaltFile: tempSaltPath(t)})
	s1 := l.Salt()
	// Mutate the returned copy.
	for i := range s1 {
		s1[i] ^= 0xff
	}
	s2 := l.Salt()
	// The internal state must be unchanged.
	if string(s1) == string(s2) {
		t.Fatalf("Salt returned live reference: mutation leaked")
	}
}

func TestConcurrentAccess(t *testing.T) {
	l := mustLabeler(t, Config{HashTenantLabels: true, SaltFile: tempSaltPath(t)})
	const workers = 32
	const iter = 500

	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iter; i++ {
				host := "tenant-" + string(rune('a'+id%26)) + ".tld"
				if got := l.Tenant(host); got == "" {
					t.Errorf("empty label")
					return
				}
				if got := l.ClientIP("198.51.100." + string(rune('0'+i%10))); got == "" {
					t.Errorf("empty client IP")
					return
				}
			}
		}(w)
	}
	wg.Wait()
}

func TestReloadWithSameFileIsStable(t *testing.T) {
	path := tempSaltPath(t)
	l1 := mustLabeler(t, Config{HashTenantLabels: true, SaltFile: path})
	host := "stable.tld"
	first := l1.Tenant(host)

	// Reload against the same file: salt must match, output must match.
	l2 := mustLabeler(t, Config{HashTenantLabels: true, SaltFile: path})
	if got := l2.Tenant(host); got != first {
		t.Fatalf("reload changed label: %q -> %q", first, got)
	}
}
