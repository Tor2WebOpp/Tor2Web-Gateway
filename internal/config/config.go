package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration structure for the gateway.
type Config struct {
	Domain      string        `yaml:"domain"`
	Email       string        `yaml:"email"`
	ProxySecret string        `yaml:"proxy_secret"`
	Cloudflare  CloudflareConf `yaml:"cloudflare"`
	Backends    []BackendConf `yaml:"backends"`
	Tor         TorConf       `yaml:"tor"`
	Pool        PoolConf      `yaml:"pool"`
	Cache       CacheConf     `yaml:"cache"`
	RateLimit   RateLimitConf `yaml:"rate_limit"`
	Security    SecurityConf  `yaml:"security"`
	Logging     LoggingConf   `yaml:"logging"`
	Metrics     MetricsConf   `yaml:"metrics"`
	Admin       AdminConf     `yaml:"admin"`
}

// CloudflareConf holds Cloudflare integration settings.
type CloudflareConf struct {
	Enabled bool   `yaml:"enabled"`
	Mode    string `yaml:"mode"` // full_strict | flexible
}

// BackendConf describes a single upstream backend.
type BackendConf struct {
	Addr   string `yaml:"addr"`
	Weight int    `yaml:"weight"`
}

// TorConf holds settings for the Tor binary and instances.
type TorConf struct {
	Binary           string        `yaml:"binary"`
	SocksBasePort    int           `yaml:"socks_base_port"`
	MinInstances     int           `yaml:"min_instances"`
	MaxInstances     int           `yaml:"max_instances"`
	DataDir          string        `yaml:"data_dir"`
	BootstrapTimeout time.Duration `yaml:"bootstrap_timeout"`
}

// PoolConf controls HTTP connection pool and circuit management.
type PoolConf struct {
	MaxIdleConnsPerHost int           `yaml:"max_idle_conns_per_host"`
	IdleTimeout         time.Duration `yaml:"idle_timeout"`
	ResponseTimeout     time.Duration `yaml:"response_timeout"`
	ConnectTimeout      time.Duration `yaml:"connect_timeout"`
	RetryAttempts       int           `yaml:"retry_attempts"`
	HealthCheckInterval time.Duration `yaml:"health_check_interval"`
	RebalanceInterval   time.Duration `yaml:"rebalance_interval"`
	ScaleCooldown       time.Duration `yaml:"scale_cooldown"`
	ScaleUpThreshold    float64       `yaml:"scale_up_threshold"`
	ScaleDownThreshold  float64       `yaml:"scale_down_threshold"`
}

// CacheConf controls in-memory response caching.
type CacheConf struct {
	Enabled         bool          `yaml:"enabled"`
	MaxSizeMB       int           `yaml:"max_size_mb"`
	DefaultTTL      time.Duration `yaml:"default_ttl"`
	StaticExtensions []string     `yaml:"static_extensions"`
}

// RateLimitConf controls per-IP and global rate limiting.
type RateLimitConf struct {
	PerIPRPS        float64       `yaml:"per_ip_rps"`
	PerIPBurst      int           `yaml:"per_ip_burst"`
	PerIPConns      int           `yaml:"per_ip_conns"`
	APIRPS          float64       `yaml:"api_rps"`
	APIBurst        int           `yaml:"api_burst"`
	GlobalRPS       float64       `yaml:"global_rps"`
	CleanupInterval time.Duration `yaml:"cleanup_interval"`
}

// SecurityConf holds security-related settings.
type SecurityConf struct {
	ProxySecretHeader string   `yaml:"proxy_secret_header"`
	AnonymizeLogs     bool     `yaml:"anonymize_logs"`
	BlockedPaths      []string `yaml:"blocked_paths"`
	BlockedMethods    []string `yaml:"blocked_methods"`
}

// LoggingConf controls log output and rotation.
type LoggingConf struct {
	Level      string `yaml:"level"`
	Format     string `yaml:"format"`
	Output     string `yaml:"output"`
	MaxSizeMB  int    `yaml:"max_size_mb"`
	MaxBackups int    `yaml:"max_backups"`
}

// MetricsConf controls Prometheus metrics exposure.
type MetricsConf struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
}

// AdminConf controls the admin Unix socket.
type AdminConf struct {
	Socket string `yaml:"socket"`
}

// Load reads the YAML config at path, validates it, and fills in defaults.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read file %q: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse yaml: %w", err)
	}

	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("config: validation: %w", err)
	}

	fillDefaults(&cfg)
	return &cfg, nil
}

// validate checks required fields and business-logic constraints.
func validate(cfg *Config) error {
	if cfg.Domain == "" {
		return errors.New("domain is required")
	}
	if len(cfg.ProxySecret) < 32 {
		return errors.New("proxy_secret must be at least 32 characters")
	}
	if len(cfg.Backends) == 0 {
		return errors.New("at least one backend is required")
	}
	if cfg.Tor.MinInstances <= 0 {
		return errors.New("tor.min_instances must be greater than 0")
	}
	return nil
}

// fillDefaults populates zero-value fields with sensible defaults.
func fillDefaults(cfg *Config) {
	if cfg.Tor.Binary == "" {
		cfg.Tor.Binary = "tor"
	}
	if cfg.Tor.SocksBasePort == 0 {
		cfg.Tor.SocksBasePort = 9050
	}
	if cfg.Tor.MaxInstances == 0 {
		cfg.Tor.MaxInstances = cfg.Tor.MinInstances * 4
	}
	if cfg.Tor.DataDir == "" {
		cfg.Tor.DataDir = "/var/lib/gateway/tor"
	}
	if cfg.Tor.BootstrapTimeout == 0 {
		cfg.Tor.BootstrapTimeout = 120 * time.Second
	}

	if cfg.Pool.MaxIdleConnsPerHost == 0 {
		cfg.Pool.MaxIdleConnsPerHost = 10
	}
	if cfg.Pool.IdleTimeout == 0 {
		cfg.Pool.IdleTimeout = 90 * time.Second
	}
	if cfg.Pool.ResponseTimeout == 0 {
		cfg.Pool.ResponseTimeout = 30 * time.Second
	}
	if cfg.Pool.ConnectTimeout == 0 {
		cfg.Pool.ConnectTimeout = 10 * time.Second
	}
	if cfg.Pool.RetryAttempts == 0 {
		cfg.Pool.RetryAttempts = 3
	}
	if cfg.Pool.HealthCheckInterval == 0 {
		cfg.Pool.HealthCheckInterval = 5 * time.Second
	}
	if cfg.Pool.RebalanceInterval == 0 {
		cfg.Pool.RebalanceInterval = 10 * time.Second
	}
	if cfg.Pool.ScaleCooldown == 0 {
		cfg.Pool.ScaleCooldown = 60 * time.Second
	}
	if cfg.Pool.ScaleUpThreshold == 0 {
		cfg.Pool.ScaleUpThreshold = 0.8
	}
	if cfg.Pool.ScaleDownThreshold == 0 {
		cfg.Pool.ScaleDownThreshold = 0.2
	}

	if cfg.Cache.MaxSizeMB == 0 {
		cfg.Cache.MaxSizeMB = 256
	}
	if cfg.Cache.DefaultTTL == 0 {
		cfg.Cache.DefaultTTL = 1 * time.Hour
	}

	if cfg.RateLimit.PerIPRPS == 0 {
		cfg.RateLimit.PerIPRPS = 30
	}
	if cfg.RateLimit.PerIPBurst == 0 {
		cfg.RateLimit.PerIPBurst = 60
	}
	if cfg.RateLimit.PerIPConns == 0 {
		cfg.RateLimit.PerIPConns = 50
	}
	if cfg.RateLimit.APIRPS == 0 {
		cfg.RateLimit.APIRPS = 5
	}
	if cfg.RateLimit.APIBurst == 0 {
		cfg.RateLimit.APIBurst = 10
	}
	if cfg.RateLimit.GlobalRPS == 0 {
		cfg.RateLimit.GlobalRPS = 5000
	}
	if cfg.RateLimit.CleanupInterval == 0 {
		cfg.RateLimit.CleanupInterval = 5 * time.Minute
	}

	if cfg.Security.ProxySecretHeader == "" {
		cfg.Security.ProxySecretHeader = "X-Proxy-Secret"
	}

	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if cfg.Logging.Format == "" {
		cfg.Logging.Format = "json"
	}
	if cfg.Logging.Output == "" {
		cfg.Logging.Output = "stdout"
	}
	if cfg.Logging.MaxSizeMB == 0 {
		cfg.Logging.MaxSizeMB = 100
	}
	if cfg.Logging.MaxBackups == 0 {
		cfg.Logging.MaxBackups = 5
	}

	if cfg.Metrics.Listen == "" {
		cfg.Metrics.Listen = ":9090"
	}

	if cfg.Admin.Socket == "" {
		cfg.Admin.Socket = "/var/run/gateway/admin.sock"
	}

	if cfg.Cloudflare.Mode == "" {
		cfg.Cloudflare.Mode = "full_strict"
	}

	for i := range cfg.Backends {
		if cfg.Backends[i].Weight == 0 {
			cfg.Backends[i].Weight = 1
		}
	}
}
