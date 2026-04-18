package shared

import (
	"math"
	"time"
)

type BackendInfo struct {
	Port        int     `json:"port"`
	Alive       bool    `json:"alive"`
	ActiveConns int     `json:"active_conns"`
	LatencyMs   int     `json:"latency_ms"`
	ErrorRate   float64 `json:"error_rate"`
	Backend     string  `json:"backend"`
}

// Score returns load score. Lower = better = gets more traffic.
// Dead backends always score math.MaxFloat64 so they sort last and are
// never picked for traffic or preserved during a scale-down.
// Formula: (active_conns * 2) + (avg_latency_ms / 100) + (error_rate_pct * 10)
func (b BackendInfo) Score() float64 {
	if !b.Alive {
		return math.MaxFloat64
	}
	return float64(b.ActiveConns*2) + float64(b.LatencyMs)/100.0 + b.ErrorRate*10.0
}

type PoolHealth struct {
	Instances    int `json:"instances"`
	Alive        int `json:"alive"`
	TotalStreams  int `json:"total_streams"`
	AvgLatencyMs int `json:"avg_latency_ms"`
}

type ScaleRequest struct {
	Target int `json:"target"`
}

type PoolStats struct {
	UptimeSec     int64 `json:"uptime_sec"`
	BytesProxied  int64 `json:"bytes_proxied"`
	CircuitsBuilt int64 `json:"circuits_built"`
}

type BackendRef struct {
	OnionAddr        string `json:"onion_addr"`
	Weight           int    `json:"weight"`
	NegativelyCached bool   `json:"negatively_cached"`
}

type FeatureSnapshot struct {
	Enabled bool           `json:"enabled"`
	Params  map[string]any `json:"params,omitempty"`
	Version uint64         `json:"version"`
}

type TenantInfo struct {
	Host             string                     `json:"host"`
	Enabled          bool                       `json:"enabled"`
	Backends         []BackendRef               `json:"backends"`
	FeatureSnapshots map[string]FeatureSnapshot `json:"feature_snapshots,omitempty"`
	Version          uint64                     `json:"version"`
}

type NodeInfo struct {
	ID              string    `json:"id"`
	Type            string    `json:"type"`
	PublicKey       string    `json:"public_key"`
	AssignedTenants []string  `json:"assigned_tenants"`
	CertSerial      string    `json:"cert_serial"`
	RegisteredAt    time.Time `json:"registered_at"`
	LastSeen        time.Time `json:"last_seen"`
}

type BlockAction string

const (
	BlockActionDrop     BlockAction = "drop"
	BlockActionTimeout  BlockAction = "timeout"
	BlockActionNotFound BlockAction = "404"
	BlockActionTooMany  BlockAction = "429"
)

func (a BlockAction) IsValid() bool {
	switch a {
	case BlockActionDrop, BlockActionTimeout, BlockActionNotFound, BlockActionTooMany:
		return true
	}
	return false
}

// MirrorInfo is the cross-package view of a single mirror domain's health.
// It is the shape carried on the hub's mirror-health SSE events and
// stored by the door's Selector.
//
// Verdict values align with the hub-side VerdictLive/VerdictDegraded/
// VerdictBlocked/VerdictUnknown constants ("live"/"degraded"/"blocked"/
// "unknown") but we keep the string here loose so the door does not have
// to import the hub package.
type MirrorInfo struct {
	Host           string   `json:"host"`
	Verdict        string   `json:"verdict"`
	ManualBlock    bool     `json:"manual_block"`
	Weight         int      `json:"weight"`
	TargetTenants  []string `json:"target_tenants,omitempty"`
	BlockedRegions []string `json:"blocked_regions,omitempty"`
	Version        uint64   `json:"version"`
}

// MirrorSnapshotPayload carries the full mirror set on connect. Version
// matches the hub's monotonic counter. Event types for mirror health
// are declared in events.go alongside the tenant/globals event types.
type MirrorSnapshotPayload struct {
	Mirrors []MirrorInfo `json:"mirrors"`
	Version uint64       `json:"version"`
}

// MirrorDeletePayload is emitted when a mirror is deregistered.
type MirrorDeletePayload struct {
	Host string `json:"host"`
}
