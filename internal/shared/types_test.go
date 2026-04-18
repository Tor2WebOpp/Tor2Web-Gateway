package shared

import (
	"encoding/json"
	"math"
	"reflect"
	"testing"
	"time"
)

func TestScore_Basic(t *testing.T) {
	// conns=23, latency=340, error=0 → (23*2) + (340/100) + (0*10) = 46 + 3.4 + 0 = 49.4
	b := BackendInfo{
		Alive:       true,
		ActiveConns: 23,
		LatencyMs:   340,
		ErrorRate:   0,
	}
	got := b.Score()
	want := 49.4
	if math.Abs(got-want) > 0.0001 {
		t.Errorf("Score() = %v, want %v", got, want)
	}
}

func TestScore_WithErrors(t *testing.T) {
	// conns=10, latency=200, error=25 → (10*2) + (200/100) + (25*10) = 20 + 2 + 250 = 272
	b := BackendInfo{
		Alive:       true,
		ActiveConns: 10,
		LatencyMs:   200,
		ErrorRate:   25,
	}
	got := b.Score()
	want := 272.0
	if math.Abs(got-want) > 0.0001 {
		t.Errorf("Score() = %v, want %v", got, want)
	}
}

// TestScore_DeadMaxFloat confirms a dead backend scores math.MaxFloat64
// so it sorts last and never wins traffic or survives scale-down.
func TestScore_DeadMaxFloat(t *testing.T) {
	dead := BackendInfo{
		Alive:       false,
		ActiveConns: 0,
		LatencyMs:   0,
		ErrorRate:   0,
	}
	if got := dead.Score(); got != math.MaxFloat64 {
		t.Errorf("Score() for dead backend = %v, want math.MaxFloat64", got)
	}
	// Live backend with large load still scores well below dead.
	live := BackendInfo{
		Alive:       true,
		ActiveConns: 1000,
		LatencyMs:   10000,
		ErrorRate:   0.99,
	}
	if live.Score() >= dead.Score() {
		t.Errorf("live backend (score=%v) must score below dead backend (score=%v)",
			live.Score(), dead.Score())
	}
}

func TestTenantInfo_JSONRoundtrip(t *testing.T) {
	in := TenantInfo{
		Host:    "example.tld",
		Enabled: true,
		Backends: []BackendRef{
			{OnionAddr: "aaa.onion", Weight: 1, NegativelyCached: false},
			{OnionAddr: "bbb.onion", Weight: 2, NegativelyCached: true},
		},
		FeatureSnapshots: map[string]FeatureSnapshot{
			"blocklist_regex": {
				Enabled: true,
				Params:  map[string]any{"default_action": "drop"},
				Version: 7,
			},
		},
		Version: 42,
	}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out TenantInfo
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Host != in.Host || out.Enabled != in.Enabled || out.Version != in.Version {
		t.Fatalf("scalar mismatch: %+v", out)
	}
	if !reflect.DeepEqual(out.Backends, in.Backends) {
		t.Fatalf("backends mismatch: %+v vs %+v", out.Backends, in.Backends)
	}
	snap, ok := out.FeatureSnapshots["blocklist_regex"]
	if !ok {
		t.Fatalf("missing feature snapshot")
	}
	if !snap.Enabled || snap.Version != 7 || snap.Params["default_action"] != "drop" {
		t.Fatalf("snapshot roundtrip failed: %+v", snap)
	}
}

func TestNodeInfo_JSONRoundtrip(t *testing.T) {
	now := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	in := NodeInfo{
		ID:              "edge-7a3c",
		Type:            "proxy",
		PublicKey:       "pubkey-hex",
		AssignedTenants: []string{"a.tld", "b.tld"},
		CertSerial:      "serial-01",
		RegisteredAt:    now,
		LastSeen:        now.Add(5 * time.Minute),
	}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out NodeInfo
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.ID != in.ID || out.Type != in.Type || out.PublicKey != in.PublicKey {
		t.Fatalf("scalar mismatch: %+v", out)
	}
	if !reflect.DeepEqual(out.AssignedTenants, in.AssignedTenants) {
		t.Fatalf("assigned tenants mismatch: %v", out.AssignedTenants)
	}
	if !out.RegisteredAt.Equal(in.RegisteredAt) || !out.LastSeen.Equal(in.LastSeen) {
		t.Fatalf("time mismatch: %v / %v", out.RegisteredAt, out.LastSeen)
	}
}

func TestFeatureSnapshot_JSONRoundtrip(t *testing.T) {
	in := FeatureSnapshot{
		Enabled: true,
		Params: map[string]any{
			"per_ip_rps":   float64(10),
			"per_ip_burst": float64(20),
		},
		Version: 3,
	}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out FeatureSnapshot
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Enabled != in.Enabled || out.Version != in.Version {
		t.Fatalf("scalar mismatch: %+v", out)
	}
	if !reflect.DeepEqual(out.Params, in.Params) {
		t.Fatalf("params mismatch: %+v", out.Params)
	}
}

func TestBlockAction_IsValid(t *testing.T) {
	valid := []BlockAction{
		BlockActionDrop,
		BlockActionTimeout,
		BlockActionNotFound,
		BlockActionTooMany,
	}
	for _, a := range valid {
		if !a.IsValid() {
			t.Errorf("expected %q valid", a)
		}
	}
	invalid := []BlockAction{"", "DROP", "403", "reject", "  drop  "}
	for _, a := range invalid {
		if a.IsValid() {
			t.Errorf("expected %q invalid", a)
		}
	}
}
