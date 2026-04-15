package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const validYAML = `
domain: example.com
email: admin@example.com
proxy_secret: "thisisaverylongsecretthatisatleast32chars"

cloudflare:
  enabled: true
  mode: full_strict

backends:
  - addr: "127.0.0.1:8080"
    weight: 2
  - addr: "127.0.0.1:8081"
    weight: 1

tor:
  binary: /usr/bin/tor
  socks_base_port: 9050
  min_instances: 3
  max_instances: 12
  data_dir: /tmp/tor-data
  bootstrap_timeout: 90s

pool:
  max_idle_conns_per_host: 20
  idle_timeout: 120s
  response_timeout: 45s
  connect_timeout: 15s
  retry_attempts: 5
  health_check_interval: 20s
  rebalance_interval: 8s
  scale_cooldown: 90s
  scale_up_threshold: 0.75
  scale_down_threshold: 0.25

cache:
  enabled: true
  max_size_mb: 512
  default_ttl: 10m
  static_extensions:
    - .js
    - .css
    - .png

rate_limit:
  per_ip_rps: 20
  per_ip_burst: 40
  per_ip_conns: 100
  api_rps: 10
  api_burst: 20
  global_rps: 5000
  cleanup_interval: 3m

security:
  proxy_secret_header: X-My-Secret
  anonymize_logs: true
  blocked_paths:
    - /admin
    - /.env
  blocked_methods:
    - TRACE

logging:
  level: debug
  format: json
  output: /var/log/gateway.log
  max_size_mb: 200
  max_backups: 10

metrics:
  enabled: true
  listen: ":9100"

admin:
  socket: /tmp/gateway-admin.sock
`

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

func TestLoad_ValidConfig(t *testing.T) {
	path := writeTempConfig(t, validYAML)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Top-level fields
	if cfg.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", cfg.Domain, "example.com")
	}
	if cfg.Email != "admin@example.com" {
		t.Errorf("Email = %q, want %q", cfg.Email, "admin@example.com")
	}
	if cfg.ProxySecret != "thisisaverylongsecretthatisatleast32chars" {
		t.Errorf("ProxySecret mismatch")
	}

	// Cloudflare
	if !cfg.Cloudflare.Enabled {
		t.Error("Cloudflare.Enabled = false, want true")
	}
	if cfg.Cloudflare.Mode != "full_strict" {
		t.Errorf("Cloudflare.Mode = %q, want %q", cfg.Cloudflare.Mode, "full_strict")
	}

	// Backends
	if len(cfg.Backends) != 2 {
		t.Fatalf("len(Backends) = %d, want 2", len(cfg.Backends))
	}
	if cfg.Backends[0].Addr != "127.0.0.1:8080" {
		t.Errorf("Backends[0].Addr = %q", cfg.Backends[0].Addr)
	}
	if cfg.Backends[0].Weight != 2 {
		t.Errorf("Backends[0].Weight = %d, want 2", cfg.Backends[0].Weight)
	}

	// Tor
	if cfg.Tor.Binary != "/usr/bin/tor" {
		t.Errorf("Tor.Binary = %q", cfg.Tor.Binary)
	}
	if cfg.Tor.SocksBasePort != 9050 {
		t.Errorf("Tor.SocksBasePort = %d", cfg.Tor.SocksBasePort)
	}
	if cfg.Tor.MinInstances != 3 {
		t.Errorf("Tor.MinInstances = %d, want 3", cfg.Tor.MinInstances)
	}
	if cfg.Tor.MaxInstances != 12 {
		t.Errorf("Tor.MaxInstances = %d, want 12", cfg.Tor.MaxInstances)
	}
	if cfg.Tor.DataDir != "/tmp/tor-data" {
		t.Errorf("Tor.DataDir = %q", cfg.Tor.DataDir)
	}
	if cfg.Tor.BootstrapTimeout != 90*time.Second {
		t.Errorf("Tor.BootstrapTimeout = %v, want 90s", cfg.Tor.BootstrapTimeout)
	}

	// Pool
	if cfg.Pool.MaxIdleConnsPerHost != 20 {
		t.Errorf("Pool.MaxIdleConnsPerHost = %d", cfg.Pool.MaxIdleConnsPerHost)
	}
	if cfg.Pool.IdleTimeout != 120*time.Second {
		t.Errorf("Pool.IdleTimeout = %v", cfg.Pool.IdleTimeout)
	}
	if cfg.Pool.ResponseTimeout != 45*time.Second {
		t.Errorf("Pool.ResponseTimeout = %v", cfg.Pool.ResponseTimeout)
	}
	if cfg.Pool.ConnectTimeout != 15*time.Second {
		t.Errorf("Pool.ConnectTimeout = %v", cfg.Pool.ConnectTimeout)
	}
	if cfg.Pool.RetryAttempts != 5 {
		t.Errorf("Pool.RetryAttempts = %d", cfg.Pool.RetryAttempts)
	}
	if cfg.Pool.HealthCheckInterval != 20*time.Second {
		t.Errorf("Pool.HealthCheckInterval = %v", cfg.Pool.HealthCheckInterval)
	}
	if cfg.Pool.RebalanceInterval != 8*time.Second {
		t.Errorf("Pool.RebalanceInterval = %v", cfg.Pool.RebalanceInterval)
	}
	if cfg.Pool.ScaleCooldown != 90*time.Second {
		t.Errorf("Pool.ScaleCooldown = %v", cfg.Pool.ScaleCooldown)
	}
	if cfg.Pool.ScaleUpThreshold != 0.75 {
		t.Errorf("Pool.ScaleUpThreshold = %v", cfg.Pool.ScaleUpThreshold)
	}
	if cfg.Pool.ScaleDownThreshold != 0.25 {
		t.Errorf("Pool.ScaleDownThreshold = %v", cfg.Pool.ScaleDownThreshold)
	}

	// Cache
	if !cfg.Cache.Enabled {
		t.Error("Cache.Enabled = false, want true")
	}
	if cfg.Cache.MaxSizeMB != 512 {
		t.Errorf("Cache.MaxSizeMB = %d, want 512", cfg.Cache.MaxSizeMB)
	}
	if cfg.Cache.DefaultTTL != 10*time.Minute {
		t.Errorf("Cache.DefaultTTL = %v, want 10m", cfg.Cache.DefaultTTL)
	}
	if len(cfg.Cache.StaticExtensions) != 3 {
		t.Errorf("len(StaticExtensions) = %d, want 3", len(cfg.Cache.StaticExtensions))
	}

	// RateLimit
	if cfg.RateLimit.PerIPRPS != 20 {
		t.Errorf("RateLimit.PerIPRPS = %v", cfg.RateLimit.PerIPRPS)
	}
	if cfg.RateLimit.PerIPBurst != 40 {
		t.Errorf("RateLimit.PerIPBurst = %d", cfg.RateLimit.PerIPBurst)
	}
	if cfg.RateLimit.PerIPConns != 100 {
		t.Errorf("RateLimit.PerIPConns = %d", cfg.RateLimit.PerIPConns)
	}
	if cfg.RateLimit.APIRPS != 10 {
		t.Errorf("RateLimit.APIRPS = %v", cfg.RateLimit.APIRPS)
	}
	if cfg.RateLimit.APIBurst != 20 {
		t.Errorf("RateLimit.APIBurst = %d", cfg.RateLimit.APIBurst)
	}
	if cfg.RateLimit.GlobalRPS != 5000 {
		t.Errorf("RateLimit.GlobalRPS = %v", cfg.RateLimit.GlobalRPS)
	}
	if cfg.RateLimit.CleanupInterval != 3*time.Minute {
		t.Errorf("RateLimit.CleanupInterval = %v", cfg.RateLimit.CleanupInterval)
	}

	// Security
	if cfg.Security.ProxySecretHeader != "X-My-Secret" {
		t.Errorf("Security.ProxySecretHeader = %q", cfg.Security.ProxySecretHeader)
	}
	if !cfg.Security.AnonymizeLogs {
		t.Error("Security.AnonymizeLogs = false, want true")
	}
	if len(cfg.Security.BlockedPaths) != 2 {
		t.Errorf("len(BlockedPaths) = %d, want 2", len(cfg.Security.BlockedPaths))
	}
	if len(cfg.Security.BlockedMethods) != 1 {
		t.Errorf("len(BlockedMethods) = %d, want 1", len(cfg.Security.BlockedMethods))
	}

	// Logging
	if cfg.Logging.Level != "debug" {
		t.Errorf("Logging.Level = %q", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("Logging.Format = %q", cfg.Logging.Format)
	}
	if cfg.Logging.Output != "/var/log/gateway.log" {
		t.Errorf("Logging.Output = %q", cfg.Logging.Output)
	}
	if cfg.Logging.MaxSizeMB != 200 {
		t.Errorf("Logging.MaxSizeMB = %d", cfg.Logging.MaxSizeMB)
	}
	if cfg.Logging.MaxBackups != 10 {
		t.Errorf("Logging.MaxBackups = %d", cfg.Logging.MaxBackups)
	}

	// Metrics
	if !cfg.Metrics.Enabled {
		t.Error("Metrics.Enabled = false, want true")
	}
	if cfg.Metrics.Listen != ":9100" {
		t.Errorf("Metrics.Listen = %q", cfg.Metrics.Listen)
	}

	// Admin
	if cfg.Admin.Socket != "/tmp/gateway-admin.sock" {
		t.Errorf("Admin.Socket = %q", cfg.Admin.Socket)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("Load() expected error for missing file, got nil")
	}
}

func TestLoad_Validation(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "empty domain",
			yaml: `
proxy_secret: "thisisaverylongsecretthatisatleast32chars"
backends:
  - addr: "127.0.0.1:8080"
    weight: 1
tor:
  min_instances: 2
`,
			wantErr: "domain is required",
		},
		{
			name: "short secret",
			yaml: `
domain: example.com
proxy_secret: "tooshort"
backends:
  - addr: "127.0.0.1:8080"
    weight: 1
tor:
  min_instances: 2
`,
			wantErr: "proxy_secret must be at least 32 characters",
		},
		{
			name: "no backends",
			yaml: `
domain: example.com
proxy_secret: "thisisaverylongsecretthatisatleast32chars"
tor:
  min_instances: 2
`,
			wantErr: "at least one backend is required",
		},
		{
			name: "min_instances zero",
			yaml: `
domain: example.com
proxy_secret: "thisisaverylongsecretthatisatleast32chars"
backends:
  - addr: "127.0.0.1:8080"
    weight: 1
tor:
  min_instances: 0
`,
			wantErr: "tor.min_instances must be greater than 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTempConfig(t, tt.yaml)
			_, err := Load(path)
			if err == nil {
				t.Fatalf("Load() expected error containing %q, got nil", tt.wantErr)
			}
			if tt.wantErr != "" {
				if !containsStr(err.Error(), tt.wantErr) {
					t.Errorf("Load() error = %q, want it to contain %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}
