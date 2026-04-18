package metrics

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
)

// saltLen is the number of random bytes used for the salt.
const saltLen = 32

// tenantHashHex is how many hex chars of the tenant digest we keep.
// 16 hex = 8 bytes = 64 bits; collision-resistant for O(10K) tenants.
const tenantHashHex = 16

// clientIPHashHex is how many hex chars of the client-IP digest we keep.
// 12 hex = 6 bytes = 48 bits; enough to distinguish clients within a scrape
// window without reversing back to the original IP.
const clientIPHashHex = 12

// TenantNone is the label used when the host is empty.
const TenantNone = "t:none"

// tenantPrefix is prepended to hashed tenant labels so dashboards can tell
// them apart from raw hostnames at a glance.
const tenantPrefix = "t:"

// Config parameters for NewLabeler.
type Config struct {
	// HashTenantLabels controls tenant-host hashing. When false, Tenant
	// returns the raw host. Client IPs are hashed regardless.
	HashTenantLabels bool

	// SaltFile is the filesystem path where the hashing salt is stored.
	// If the file does not exist it is created with 32 random bytes and
	// mode 0600. If it exists with looser permissions, NewLabeler fails.
	SaltFile string
}

// Labeler produces stable, OPSEC-safe label values for Prometheus metrics.
// The zero value is not usable — construct via NewLabeler.
type Labeler struct {
	hashTenant bool

	// salt is kept unexported and never handed out directly; Salt()
	// returns a defensive copy.
	salt []byte

	// pool reuses SHA-256 hashers to avoid per-request allocation.
	pool sync.Pool
}

// NewLabeler returns a Labeler configured by cfg. If cfg.HashTenantLabels
// is false, SaltFile may still be provided (client-IP hashing uses it);
// if SaltFile is empty in that case, a random in-memory salt is generated
// for the process lifetime.
func NewLabeler(cfg Config) (*Labeler, error) {
	salt, err := loadOrCreateSalt(cfg.SaltFile)
	if err != nil {
		return nil, err
	}
	l := &Labeler{
		hashTenant: cfg.HashTenantLabels,
		salt:       salt,
	}
	l.pool.New = func() any { return sha256.New() }
	return l, nil
}

// Tenant returns the label value for a tenant host. It is deterministic
// within a process for a given salt: two calls with the same host yield
// the same result.
//
// If host is empty the function returns TenantNone, regardless of
// configuration. If hashing is disabled, the raw host is returned.
func (l *Labeler) Tenant(host string) string {
	if host == "" {
		return TenantNone
	}
	if !l.hashTenant {
		return host
	}
	return tenantPrefix + l.hashHex(host, tenantHashHex)
}

// ClientIP returns the label value for a client IP. Client IPs are always
// hashed — raw values never appear in metrics.
func (l *Labeler) ClientIP(ip string) string {
	if ip == "" {
		return ""
	}
	return l.hashHex(ip, clientIPHashHex)
}

// Salt returns a defensive copy of the salt. Callers must not rely on
// this for anything except tests; the copy protects the underlying
// secret from accidental mutation.
func (l *Labeler) Salt() []byte {
	out := make([]byte, len(l.salt))
	copy(out, l.salt)
	return out
}

// hashHex computes hex(sha256(salt || input))[:n].
func (l *Labeler) hashHex(input string, n int) string {
	h := l.pool.Get().(interface {
		io.Writer
		Sum([]byte) []byte
		Reset()
	})
	h.Reset()
	_, _ = h.Write(l.salt)
	_, _ = h.Write([]byte(input))
	sum := h.Sum(nil)
	l.pool.Put(h)

	full := hex.EncodeToString(sum)
	if n >= len(full) {
		return full
	}
	return full[:n]
}

// loadOrCreateSalt reads a salt from path. If the file does not exist it
// is created with 32 random bytes and mode 0600. If the file exists with
// permissions looser than 0600, an error is returned.
//
// When path is empty a random in-memory salt is generated and returned;
// this is only safe when the process has no need for stable labels
// across restarts.
func loadOrCreateSalt(path string) ([]byte, error) {
	if path == "" {
		s := make([]byte, saltLen)
		if _, err := io.ReadFull(rand.Reader, s); err != nil {
			return nil, fmt.Errorf("metrics: generate ephemeral salt: %w", err)
		}
		return s, nil
	}

	info, err := os.Stat(path)
	switch {
	case err == nil:
		if err := checkSaltPerms(info); err != nil {
			return nil, err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("metrics: read salt: %w", err)
		}
		if len(data) < 16 {
			return nil, fmt.Errorf("metrics: salt file %s too short: %d bytes", path, len(data))
		}
		return data, nil
	case errors.Is(err, os.ErrNotExist):
		return createSaltFile(path)
	default:
		return nil, fmt.Errorf("metrics: stat salt file: %w", err)
	}
}

// createSaltFile writes a fresh random salt with mode 0600.
func createSaltFile(path string) ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("metrics: read random: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("metrics: create salt file: %w", err)
	}
	if _, err := f.Write(salt); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("metrics: write salt: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("metrics: close salt: %w", err)
	}
	// Re-chmod defensively in case OS umask interfered (no-op on Windows).
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, fmt.Errorf("metrics: chmod salt: %w", err)
		}
	}
	return salt, nil
}

// checkSaltPerms rejects salts stored with looser permissions than 0600.
// On Windows, Go reports synthetic permission bits and real ACLs live
// elsewhere — the check is skipped there.
func checkSaltPerms(info os.FileInfo) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	mode := info.Mode().Perm()
	// Any bit outside 0600 means the file is readable or writable by
	// someone other than the owner. Reject.
	if mode&^0o600 != 0 {
		return fmt.Errorf("metrics: salt file %s has permissions %#o, want 0600", info.Name(), mode)
	}
	return nil
}
