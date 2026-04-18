package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Mode values for the gateway process.
const (
	ModeLocal  = "local"
	ModeRemote = "remote"
)

// NodeType values identify the role of a gateway process in a deployment.
// "door" is reserved for P2 but accepted at config time to avoid churn.
const (
	NodeTypeProxy = "proxy"
	NodeTypeHub   = "hub"
	NodeTypeDoor  = "door"
	NodeTypeLocal = "local"
)

// Transport kinds for edge <-> hub communication.
const (
	TransportWireguard   = "wireguard"
	TransportHTTPSTunnel = "https_tunnel"
	TransportSOCKS5TLS   = "socks5_tls"
)

// Config is the top-level configuration structure for the gateway.
type Config struct {
	// Deployment-level fields (bootstrap, P1).
	Mode           string       `yaml:"mode"`
	NodeType       string       `yaml:"node_type"`
	Transport      TransportConf `yaml:"transport"`
	MTLS           MTLSConf     `yaml:"mtls"`
	HubURL         string       `yaml:"hub_url"`
	NodeID         string       `yaml:"node_id"`
	NodeSecretFile string       `yaml:"node_secret_file"`
	Hub            HubConf      `yaml:"hub"`

	// Legacy / single-tenant fields preserved for backward compatibility.
	Domain      string         `yaml:"domain"`
	Email       string         `yaml:"email"`
	ProxySecret string         `yaml:"proxy_secret"`
	Cloudflare  CloudflareConf `yaml:"cloudflare"`
	Backends    []BackendConf  `yaml:"backends"`
	Tor         TorConf        `yaml:"tor"`
	Pool        PoolConf       `yaml:"pool"`
	Cache       CacheConf      `yaml:"cache"`
	RateLimit   RateLimitConf  `yaml:"rate_limit"`
	Security    SecurityConf   `yaml:"security"`
	Logging     LoggingConf    `yaml:"logging"`
	Metrics     MetricsConf    `yaml:"metrics"`
	Admin       AdminConf      `yaml:"admin"`

	// Door carries gateway-door specific runtime config. Only populated
	// when NodeType==door; other node types leave it zero-valued.
	Door DoorConf `yaml:"door"`
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
	// QuarantineGrace controls how long an instance stays quarantined
	// (out of the load-balancer, Tor process still running, still probed)
	// before it is replaced. A probe success during this window clears
	// the quarantine without the cost of a new Tor bootstrap. Zero falls
	// back to immediate replacement on threshold crossing.
	QuarantineGrace time.Duration `yaml:"quarantine_grace"`
}

// CacheConf controls in-memory response caching.
type CacheConf struct {
	Enabled          bool          `yaml:"enabled"`
	MaxSizeMB        int           `yaml:"max_size_mb"`
	DefaultTTL       time.Duration `yaml:"default_ttl"`
	StaticExtensions []string      `yaml:"static_extensions"`
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
	Enabled bool             `yaml:"enabled"`
	Listen  string           `yaml:"listen"`
	OPSEC   MetricsOPSECConf `yaml:"opsec"`
}

// MetricsOPSECConf controls privacy-preserving metric label handling.
type MetricsOPSECConf struct {
	HashTenantLabels    bool   `yaml:"hash_tenant_labels"`
	TenantLabelSaltFile string `yaml:"tenant_label_salt_file"`
}

// AdminConf controls the admin Unix socket and hidden admin gate slug/tokens.
//
// P3 fields (SessionIdleTTL, SessionAbsoluteTTL, AuditDataDir, Lockout) tune
// the runtime admin handler. They are only consulted when Enabled=true; with
// the gate disabled they are loaded but ignored. Sensible defaults are filled
// in by fillDefaults so a minimal admin: block (enabled + slug + tokens)
// continues to work without restating every knob.
type AdminConf struct {
	Socket  string `yaml:"socket"`
	Enabled bool   `yaml:"enabled"`
	Slug    string `yaml:"slug"`
	Token1  string `yaml:"token1"`
	Token2  string `yaml:"token2"`

	// SessionIdleTTL bounds the idle window between admin requests before
	// the session cookie is considered stale and the operator is bounced
	// back through the URL gate. Default: 15m.
	SessionIdleTTL time.Duration `yaml:"session_idle_ttl"`

	// SessionAbsoluteTTL caps the maximum lifetime of a single admin
	// session regardless of activity. After this elapses the session is
	// purged even if requests are still arriving on it. Default: 8h.
	SessionAbsoluteTTL time.Duration `yaml:"session_absolute_ttl"`

	// AuditDataDir is the on-disk directory for the append-only audit log.
	// Per-day JSONL files plus the BoltDB index live here. The default is
	// derived per node type by fillDefaults so a hub does not collide with
	// the proxy/door binaries on the same host.
	AuditDataDir string `yaml:"audit_data_dir"`

	// Lockout governs the per-IP-hash failed-attempt tracker that promotes
	// abusive clients into a backoff/banned state. The thresholds and
	// windows are configurable so operators with unusual traffic shapes
	// (e.g. CI probes) can loosen them rather than disable the gate.
	Lockout LockoutConf `yaml:"lockout"`
}

// LockoutConf parameterises the two-tier per-IP lockout for the admin gate.
//
// Soft tier: SoftThreshold failures inside SoftWindow flips the IP into a
// SoftBackoff state during which all admin paths return 404 with no gate
// evaluation. Hard tier: HardThreshold failures inside HardWindow flips into
// a HardBan state for HardBan duration. Either tier resets immediately on a
// successful admin entry from the same IP hash.
type LockoutConf struct {
	SoftThreshold int           `yaml:"soft_threshold"`
	SoftWindow    time.Duration `yaml:"soft_window"`
	SoftBackoff   time.Duration `yaml:"soft_backoff"`
	HardThreshold int           `yaml:"hard_threshold"`
	HardWindow    time.Duration `yaml:"hard_window"`
	HardBan       time.Duration `yaml:"hard_ban"`
}

// TransportConf selects and parameterises the edge<->hub transport.
type TransportConf struct {
	Kind        string          `yaml:"kind"`
	Wireguard   WireguardConf   `yaml:"wireguard"`
	HTTPSTunnel HTTPSTunnelConf `yaml:"https_tunnel"`
	SOCKS5TLS   SOCKS5TLSConf   `yaml:"socks5_tls"`
}

// WireguardConf describes the wg-quick style peer relationship toward the hub.
type WireguardConf struct {
	Interface      string `yaml:"interface"`
	PrivateKeyFile string `yaml:"private_key_file"`
	PeerPubkey     string `yaml:"peer_pubkey"`
	PeerEndpoint   string `yaml:"peer_endpoint"`
	PeerAllowedIPs string `yaml:"peer_allowed_ips"`
	SelfIP         string `yaml:"self_ip"`
}

// HTTPSTunnelConf describes the WebSocket-over-HTTPS transport.
type HTTPSTunnelConf struct {
	HubURL     string `yaml:"hub_url"`
	CACertFile string `yaml:"ca_cert_file"`
}

// SOCKS5TLSConf describes the raw-SOCKS5-inside-TLS transport.
type SOCKS5TLSConf struct {
	HubAddr    string `yaml:"hub_addr"`
	AdminAddr  string `yaml:"admin_addr"`
	CACertFile string `yaml:"ca_cert_file"`
}

// MTLSConf holds the client-side mTLS identity used by edges.
type MTLSConf struct {
	ClientCertFile string `yaml:"client_cert_file"`
	ClientKeyFile  string `yaml:"client_key_file"`
}

// HubConf holds hub-side bootstrap config; only populated when NodeType==hub.
type HubConf struct {
	ListenAdmin string `yaml:"listen_admin"`
	ListenWG    string `yaml:"listen_wg"`
	CACertFile  string `yaml:"ca_cert_file"`
	CAKeyFile   string `yaml:"ca_key_file"`
	DataDir     string `yaml:"data_dir"`
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

	// Legacy YAML detection: no explicit mode but classic single-tenant
	// fields are populated — treat as local mode. The hub package will
	// synthesize an implicit TenantConf from Domain+Backends in wave 2.
	if cfg.Mode == "" && len(cfg.Backends) > 0 {
		cfg.Mode = ModeLocal
	}

	fillDefaults(&cfg)

	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("config: validation: %w", err)
	}

	return &cfg, nil
}

// validate checks required fields and business-logic constraints.
func validate(cfg *Config) error {
	if !isValidMode(cfg.Mode) {
		return fmt.Errorf("mode must be one of %q or %q", ModeLocal, ModeRemote)
	}
	if !isValidNodeType(cfg.NodeType) {
		return fmt.Errorf("node_type must be one of proxy|hub|door|local, got %q", cfg.NodeType)
	}

	if cfg.Mode == ModeRemote {
		if cfg.HubURL == "" {
			return errors.New("hub_url is required when mode=remote")
		}
		if !isValidTransport(cfg.Transport.Kind) {
			return fmt.Errorf("transport.kind must be wireguard|https_tunnel|socks5_tls when mode=remote, got %q", cfg.Transport.Kind)
		}
	}

	// In local mode the classic single-tenant fields remain required
	// so existing deployments keep working.
	if cfg.Mode == ModeLocal {
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
	}

	// Cross-field Tor sanity. Only enforced when max is explicitly set —
	// fillDefaults derives max from min*4 so a zero-valued max is already
	// guaranteed to be >= min via the default path.
	if cfg.Tor.MaxInstances > 0 && cfg.Tor.MinInstances > cfg.Tor.MaxInstances {
		return errors.New("tor.min_instances must be <= max_instances")
	}
	if cfg.Tor.SocksBasePort > 0 && cfg.Tor.SocksBasePort+cfg.Tor.MaxInstances >= 65535 {
		return errors.New("tor.socks_base_port + max_instances exceeds port range")
	}
	// Pool scale thresholds must not invert — a scale_up_threshold lower
	// than scale_down_threshold would oscillate between growing and
	// shrinking on every evaluation tick.
	if cfg.Pool.ScaleUpThreshold <= cfg.Pool.ScaleDownThreshold {
		return errors.New("pool.scale_up_threshold must be > scale_down_threshold")
	}

	if cfg.Admin.Enabled {
		if len(cfg.Admin.Slug) < 32 {
			return errors.New("admin.slug must be at least 32 characters when admin.enabled")
		}
		if len(cfg.Admin.Token1) < 32 {
			return errors.New("admin.token1 must be at least 32 characters when admin.enabled")
		}
		if len(cfg.Admin.Token2) < 32 {
			return errors.New("admin.token2 must be at least 32 characters when admin.enabled")
		}
		// P3 admin handler: idle window must fit inside the absolute
		// window, otherwise the absolute cap is meaningless.
		if cfg.Admin.SessionIdleTTL >= cfg.Admin.SessionAbsoluteTTL {
			return fmt.Errorf("admin.session_idle_ttl (%s) must be less than admin.session_absolute_ttl (%s)",
				cfg.Admin.SessionIdleTTL, cfg.Admin.SessionAbsoluteTTL)
		}
		// Lockout thresholds and windows must be positive — a zero
		// threshold disables the tier silently and we'd rather fail
		// loudly so operators notice the misconfiguration.
		if cfg.Admin.Lockout.SoftThreshold <= 0 {
			return errors.New("admin.lockout.soft_threshold must be > 0 when admin.enabled")
		}
		if cfg.Admin.Lockout.SoftWindow <= 0 {
			return errors.New("admin.lockout.soft_window must be > 0 when admin.enabled")
		}
		if cfg.Admin.Lockout.SoftBackoff <= 0 {
			return errors.New("admin.lockout.soft_backoff must be > 0 when admin.enabled")
		}
		if cfg.Admin.Lockout.HardThreshold <= 0 {
			return errors.New("admin.lockout.hard_threshold must be > 0 when admin.enabled")
		}
		if cfg.Admin.Lockout.HardWindow <= 0 {
			return errors.New("admin.lockout.hard_window must be > 0 when admin.enabled")
		}
		if cfg.Admin.Lockout.HardBan <= 0 {
			return errors.New("admin.lockout.hard_ban must be > 0 when admin.enabled")
		}
	}

	return nil
}

// fillDefaults populates zero-value fields with sensible defaults.
func fillDefaults(cfg *Config) {
	if cfg.Mode == "" {
		cfg.Mode = ModeLocal
	}
	if cfg.NodeType == "" {
		cfg.NodeType = NodeTypeLocal
	}
	if cfg.Mode == ModeRemote && cfg.Transport.Kind == "" {
		cfg.Transport.Kind = TransportWireguard
	}

	if cfg.Tor.Binary == "" {
		cfg.Tor.Binary = "tor"
	}
	if cfg.Tor.SocksBasePort == 0 {
		cfg.Tor.SocksBasePort = 9050
	}
	// Defaults for the Tor pool: config.example.yaml ships the recommended
	// 10/20 pair (tuned to real Tor hidden-service reachability: ~30% of
	// onions unreachable at any moment, stalls of 30-60s routine). Zero
	// MinInstances is kept as an explicit opt-out sentinel so hub-mode
	// deployments and tests can skip torpool startup entirely; we default
	// MaxInstances only when MinInstances is non-zero.
	if cfg.Tor.MinInstances > 0 && cfg.Tor.MaxInstances == 0 {
		cfg.Tor.MaxInstances = 20
	}
	if cfg.Tor.DataDir == "" {
		cfg.Tor.DataDir = "/var/lib/gateway/tor"
	}
	if cfg.Tor.BootstrapTimeout == 0 {
		cfg.Tor.BootstrapTimeout = 90 * time.Second
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
	// 3 x 60s = 3 minutes of grace before an instance is replaced. Matches
	// the known 30-60s stall windows during intro-point refresh and keeps
	// transient hangs from cascading into replacement storms.
	if cfg.Pool.HealthCheckInterval == 0 {
		cfg.Pool.HealthCheckInterval = 60 * time.Second
	}
	if cfg.Pool.RebalanceInterval == 0 {
		cfg.Pool.RebalanceInterval = 15 * time.Second
	}
	if cfg.Pool.ScaleCooldown == 0 {
		cfg.Pool.ScaleCooldown = 120 * time.Second
	}
	if cfg.Pool.QuarantineGrace == 0 {
		cfg.Pool.QuarantineGrace = 5 * time.Minute
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
		cfg.Admin.Socket = "/run/gateway/torpool.sock"
	}

	// P3 admin defaults. These are loaded unconditionally so that flipping
	// Admin.Enabled at runtime (or in tests) yields the same behaviour as a
	// fresh boot with the gate already on.
	if cfg.Admin.SessionIdleTTL == 0 {
		cfg.Admin.SessionIdleTTL = 15 * time.Minute
	}
	if cfg.Admin.SessionAbsoluteTTL == 0 {
		cfg.Admin.SessionAbsoluteTTL = 8 * time.Hour
	}
	if cfg.Admin.AuditDataDir == "" {
		// Per-node-type default keeps three binaries on the same host
		// from clobbering each other's audit history.
		switch cfg.NodeType {
		case NodeTypeHub:
			cfg.Admin.AuditDataDir = "/var/lib/gateway/hub/audit"
		case NodeTypeDoor:
			cfg.Admin.AuditDataDir = "/var/lib/gateway/door/audit"
		default:
			cfg.Admin.AuditDataDir = "/var/lib/gateway/proxy/audit"
		}
	}
	if cfg.Admin.Lockout.SoftThreshold == 0 {
		cfg.Admin.Lockout.SoftThreshold = 3
	}
	if cfg.Admin.Lockout.SoftWindow == 0 {
		cfg.Admin.Lockout.SoftWindow = 60 * time.Second
	}
	if cfg.Admin.Lockout.SoftBackoff == 0 {
		cfg.Admin.Lockout.SoftBackoff = 30 * time.Second
	}
	if cfg.Admin.Lockout.HardThreshold == 0 {
		cfg.Admin.Lockout.HardThreshold = 10
	}
	if cfg.Admin.Lockout.HardWindow == 0 {
		cfg.Admin.Lockout.HardWindow = 10 * time.Minute
	}
	if cfg.Admin.Lockout.HardBan == 0 {
		cfg.Admin.Lockout.HardBan = 1 * time.Hour
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

func isValidMode(m string) bool {
	switch m {
	case ModeLocal, ModeRemote:
		return true
	}
	return false
}

func isValidNodeType(n string) bool {
	switch n {
	case NodeTypeProxy, NodeTypeHub, NodeTypeDoor, NodeTypeLocal:
		return true
	}
	return false
}

func isValidTransport(k string) bool {
	switch k {
	case TransportWireguard, TransportHTTPSTunnel, TransportSOCKS5TLS:
		return true
	}
	return false
}
