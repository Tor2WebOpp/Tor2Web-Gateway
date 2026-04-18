package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}

const tenantYAML = `
host: example.tld
enabled: true

backends:
  - addr: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad.onion"
    weight: 1
  - addr: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbd.onion"
    weight: 2

features:
  blocklist_regex:
    enabled: true
  rate_limit:
    enabled: true

stealth_hs:
  enabled: true
  client_auths:
    - onion: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbd.onion"
      auth_private_key_file: /var/lib/gateway/stealth/example-bbb.auth_private

negative_cache:
  enabled: true
  ttl: 5m
  failure_threshold: 5

abuse_api:
  enabled: true
  path: /_abuse
  notify_email: ops@example.tld

assigned_nodes:
  - edge-7a3c
  - edge-1d2e
`

func TestLoadTenantFile_RoundTrip(t *testing.T) {
	path := writeTempFile(t, "example.tld.yaml", tenantYAML)
	tc, err := LoadTenantFile(path)
	if err != nil {
		t.Fatalf("LoadTenantFile error = %v", err)
	}
	if tc.Host != "example.tld" {
		t.Errorf("Host = %q", tc.Host)
	}
	if !tc.Enabled {
		t.Error("Enabled = false, want true")
	}
	if len(tc.Backends) != 2 {
		t.Fatalf("len(Backends) = %d, want 2", len(tc.Backends))
	}
	if tc.Backends[1].Weight != 2 {
		t.Errorf("Backends[1].Weight = %d, want 2", tc.Backends[1].Weight)
	}
	if !tc.Features["blocklist_regex"].Enabled {
		t.Error("features.blocklist_regex not enabled")
	}
	if !tc.StealthHS.Enabled || len(tc.StealthHS.ClientAuths) != 1 {
		t.Error("StealthHS not parsed correctly")
	}
	if tc.NegativeCache.TTL != 5*time.Minute {
		t.Errorf("NegativeCache.TTL = %v", tc.NegativeCache.TTL)
	}
	if tc.NegativeCache.FailureThreshold != 5 {
		t.Errorf("NegativeCache.FailureThreshold = %d", tc.NegativeCache.FailureThreshold)
	}
	if tc.AbuseAPI.Path != "/_abuse" || tc.AbuseAPI.NotifyEmail != "ops@example.tld" {
		t.Errorf("AbuseAPI = %+v", tc.AbuseAPI)
	}
	if len(tc.AssignedNodes) != 2 {
		t.Errorf("len(AssignedNodes) = %d, want 2", len(tc.AssignedNodes))
	}
}

func TestLoadTenantFile_MissingHost(t *testing.T) {
	y := `
backends:
  - addr: "aaad.onion"
    weight: 1
`
	path := writeTempFile(t, "bad.yaml", y)
	if _, err := LoadTenantFile(path); err == nil {
		t.Fatal("expected error for missing host")
	}
}

func TestLoadTenantFile_NoBackends(t *testing.T) {
	y := `
host: example.tld
`
	path := writeTempFile(t, "bad.yaml", y)
	if _, err := LoadTenantFile(path); err == nil {
		t.Fatal("expected error for no backends")
	}
}

func TestLoadTenantFile_WeightDefault(t *testing.T) {
	y := `
host: example.tld
backends:
  - addr: "aaad.onion"
`
	path := writeTempFile(t, "t.yaml", y)
	tc, err := LoadTenantFile(path)
	if err != nil {
		t.Fatalf("LoadTenantFile: %v", err)
	}
	if tc.Backends[0].Weight != 1 {
		t.Errorf("Backends[0].Weight = %d, want default 1", tc.Backends[0].Weight)
	}
}

const globalsYAML = `
features:
  blocklist_regex:
    enabled: true
  geoip:
    enabled: false

block_response:
  default: drop
  timeout_seconds: 30

headers:
  strip_upstream:
    - Server
    - X-Powered-By
  add_downstream:
    - name: X-Frame-Options
      value: DENY
`

func TestLoadGlobalsFile_RoundTrip(t *testing.T) {
	path := writeTempFile(t, "globals.yaml", globalsYAML)
	g, err := LoadGlobalsFile(path)
	if err != nil {
		t.Fatalf("LoadGlobalsFile error = %v", err)
	}
	if !g.Features["blocklist_regex"].Enabled {
		t.Error("blocklist_regex not enabled")
	}
	if g.Features["geoip"].Enabled {
		t.Error("geoip should be disabled")
	}
	if g.BlockResponse.Default != BlockDrop {
		t.Errorf("BlockResponse.Default = %q", g.BlockResponse.Default)
	}
	if g.BlockResponse.TimeoutSeconds != 30 {
		t.Errorf("BlockResponse.TimeoutSeconds = %d", g.BlockResponse.TimeoutSeconds)
	}
	if len(g.Headers.StripUpstream) != 2 {
		t.Errorf("len(StripUpstream) = %d", len(g.Headers.StripUpstream))
	}
	if len(g.Headers.AddDownstream) != 1 || g.Headers.AddDownstream[0].Name != "X-Frame-Options" {
		t.Errorf("AddDownstream = %+v", g.Headers.AddDownstream)
	}
}

func TestLoadGlobalsFile_InvalidBlockResponse(t *testing.T) {
	y := `
block_response:
  default: explode
`
	path := writeTempFile(t, "globals.yaml", y)
	_, err := LoadGlobalsFile(path)
	if err == nil {
		t.Fatal("expected error for invalid block_response.default")
	}
	if !containsStr(err.Error(), "block_response.default must be") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadGlobalsFile_AllValidBlockResponses(t *testing.T) {
	for _, v := range []string{BlockDrop, BlockTimeout, Block404, Block429} {
		y := "block_response:\n  default: " + v + "\n"
		path := writeTempFile(t, "g.yaml", y)
		if _, err := LoadGlobalsFile(path); err != nil {
			t.Errorf("block_response=%q rejected: %v", v, err)
		}
	}
}

func TestLoadGlobalsFile_EmptyBlockResponseAllowed(t *testing.T) {
	// empty default means "use hardcoded fallback" — accept.
	y := "features: {}\n"
	path := writeTempFile(t, "g.yaml", y)
	if _, err := LoadGlobalsFile(path); err != nil {
		t.Errorf("empty globals rejected: %v", err)
	}
}

func TestLoadTenantFile_MissingFile(t *testing.T) {
	if _, err := LoadTenantFile("/nonexistent/tenant.yaml"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadGlobalsFile_MissingFile(t *testing.T) {
	if _, err := LoadGlobalsFile("/nonexistent/globals.yaml"); err == nil {
		t.Fatal("expected error for missing file")
	}
}
