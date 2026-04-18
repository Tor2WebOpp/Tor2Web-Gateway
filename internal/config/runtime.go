package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Block-response modes for request-level drop decisions.
const (
	BlockDrop    = "drop"
	BlockTimeout = "timeout"
	Block404     = "404"
	Block429     = "429"
)

// FeatureConf is the uniform shape every feature toggle uses, matching
// the resolution order: per-tenant override → globals → hardcoded default.
type FeatureConf struct {
	Enabled bool           `yaml:"enabled"`
	Params  map[string]any `yaml:"params,omitempty"`
}

// TenantConf is the runtime descriptor of a single tenant; one file per host.
type TenantConf struct {
	Host          string                 `yaml:"host"`
	Enabled       bool                   `yaml:"enabled"`
	Backends      []BackendConf          `yaml:"backends"`
	Features      map[string]FeatureConf `yaml:"features,omitempty"`
	StealthHS     StealthHSConf          `yaml:"stealth_hs"`
	NegativeCache NegativeCacheConf      `yaml:"negative_cache"`
	AbuseAPI      AbuseAPIConf           `yaml:"abuse_api"`
	AssignedNodes []string               `yaml:"assigned_nodes,omitempty"`
}

// StealthHSConf holds Tor client-auth entries for stealth hidden services.
type StealthHSConf struct {
	Enabled     bool               `yaml:"enabled"`
	ClientAuths []ClientAuthEntry  `yaml:"client_auths"`
}

// ClientAuthEntry is one stealth-HS client-auth mounted into Tor instances.
type ClientAuthEntry struct {
	Onion              string `yaml:"onion"`
	AuthPrivateKeyFile string `yaml:"auth_private_key_file"`
}

// NegativeCacheConf tracks how long dead backends stay blacklisted.
type NegativeCacheConf struct {
	Enabled          bool          `yaml:"enabled"`
	TTL              time.Duration `yaml:"ttl"`
	FailureThreshold int           `yaml:"failure_threshold"`
}

// AbuseAPIConf controls the optional abuse-reporting endpoint.
type AbuseAPIConf struct {
	Enabled     bool   `yaml:"enabled"`
	Path        string `yaml:"path"`
	NotifyEmail string `yaml:"notify_email"`
}

// GlobalsConf is the runtime defaults file applied under every tenant.
type GlobalsConf struct {
	Features      map[string]FeatureConf `yaml:"features,omitempty"`
	BlockResponse BlockResponseConf      `yaml:"block_response"`
	Headers       HeadersConf            `yaml:"headers"`
}

// BlockResponseConf configures what clients see when a request is denied.
type BlockResponseConf struct {
	Default        string `yaml:"default"`
	TimeoutSeconds int    `yaml:"timeout_seconds"`
}

// HeadersConf describes header-rewriting rules applied globally.
type HeadersConf struct {
	StripUpstream []string     `yaml:"strip_upstream"`
	AddDownstream []HeaderRule `yaml:"add_downstream"`
}

// HeaderRule is one name/value pair used by HeadersConf.
type HeaderRule struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

// LoadTenantFile parses one tenant YAML file and validates it.
func LoadTenantFile(path string) (*TenantConf, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("tenant: read file %q: %w", path, err)
	}

	var t TenantConf
	if err := yaml.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("tenant: parse yaml: %w", err)
	}
	if err := validateTenant(&t); err != nil {
		return nil, fmt.Errorf("tenant: validation: %w", err)
	}
	return &t, nil
}

// LoadGlobalsFile parses a globals.yaml and validates its block_response.
func LoadGlobalsFile(path string) (*GlobalsConf, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("globals: read file %q: %w", path, err)
	}

	var g GlobalsConf
	if err := yaml.Unmarshal(data, &g); err != nil {
		return nil, fmt.Errorf("globals: parse yaml: %w", err)
	}
	if err := validateGlobals(&g); err != nil {
		return nil, fmt.Errorf("globals: validation: %w", err)
	}
	return &g, nil
}

func validateTenant(t *TenantConf) error {
	if t.Host == "" {
		return errors.New("host is required")
	}
	if len(t.Backends) == 0 {
		return errors.New("at least one backend is required")
	}
	for i := range t.Backends {
		if t.Backends[i].Addr == "" {
			return fmt.Errorf("backends[%d].addr is required", i)
		}
		if t.Backends[i].Weight == 0 {
			t.Backends[i].Weight = 1
		}
	}
	return nil
}

func validateGlobals(g *GlobalsConf) error {
	if g.BlockResponse.Default != "" && !isValidBlockResponse(g.BlockResponse.Default) {
		return fmt.Errorf("block_response.default must be drop|timeout|404|429, got %q", g.BlockResponse.Default)
	}
	return nil
}

func isValidBlockResponse(v string) bool {
	switch v {
	case BlockDrop, BlockTimeout, Block404, Block429:
		return true
	}
	return false
}
