package shared

import (
	"encoding/json"
	"time"
)

type ConfigStreamEventType string

const (
	EventSnapshot      ConfigStreamEventType = "snapshot"
	EventTenantUpsert  ConfigStreamEventType = "tenant_upsert"
	EventTenantDelete  ConfigStreamEventType = "tenant_delete"
	EventGlobalsUpdate ConfigStreamEventType = "globals_update"

	// Mirror health events published by the hub's MirrorRegistry. All
	// authenticated mTLS peers receive these regardless of tenant
	// assignment: doors pick redirect targets from the live mirror set,
	// and proxies log the state for diagnostics.
	EventMirrorSnapshot ConfigStreamEventType = "mirror_snapshot"
	EventMirrorUpsert   ConfigStreamEventType = "mirror_upsert"
	EventMirrorDelete   ConfigStreamEventType = "mirror_delete"
)

type ConfigStreamEvent struct {
	Type      ConfigStreamEventType `json:"type"`
	Data      json.RawMessage       `json:"data,omitempty"`
	Timestamp time.Time             `json:"timestamp"`
}

type SnapshotPayload struct {
	Tenants []TenantInfo    `json:"tenants"`
	Globals json.RawMessage `json:"globals,omitempty"`
	Version uint64          `json:"version"`
}

type TenantDeletePayload struct {
	Host string `json:"host"`
}

func NewSnapshotEvent(tenants []TenantInfo, globals json.RawMessage, version uint64) (ConfigStreamEvent, error) {
	payload, err := json.Marshal(SnapshotPayload{
		Tenants: tenants,
		Globals: globals,
		Version: version,
	})
	if err != nil {
		return ConfigStreamEvent{}, err
	}
	return ConfigStreamEvent{
		Type:      EventSnapshot,
		Data:      payload,
		Timestamp: time.Now().UTC(),
	}, nil
}

func NewTenantUpsertEvent(t TenantInfo) (ConfigStreamEvent, error) {
	payload, err := json.Marshal(t)
	if err != nil {
		return ConfigStreamEvent{}, err
	}
	return ConfigStreamEvent{
		Type:      EventTenantUpsert,
		Data:      payload,
		Timestamp: time.Now().UTC(),
	}, nil
}

func NewTenantDeleteEvent(host string) (ConfigStreamEvent, error) {
	payload, err := json.Marshal(TenantDeletePayload{Host: host})
	if err != nil {
		return ConfigStreamEvent{}, err
	}
	return ConfigStreamEvent{
		Type:      EventTenantDelete,
		Data:      payload,
		Timestamp: time.Now().UTC(),
	}, nil
}

func NewGlobalsEvent(globals json.RawMessage) ConfigStreamEvent {
	return ConfigStreamEvent{
		Type:      EventGlobalsUpdate,
		Data:      globals,
		Timestamp: time.Now().UTC(),
	}
}

// NewMirrorSnapshotEvent returns the full-mirror-set bootstrap event
// subscribers receive on first connect. Version tracks the hub's
// monotonic counter.
func NewMirrorSnapshotEvent(mirrors []MirrorInfo, version uint64) (ConfigStreamEvent, error) {
	payload, err := json.Marshal(MirrorSnapshotPayload{
		Mirrors: mirrors,
		Version: version,
	})
	if err != nil {
		return ConfigStreamEvent{}, err
	}
	return ConfigStreamEvent{
		Type:      EventMirrorSnapshot,
		Data:      payload,
		Timestamp: time.Now().UTC(),
	}, nil
}

// NewMirrorUpsertEvent encodes a single-mirror upsert delta.
func NewMirrorUpsertEvent(m MirrorInfo) (ConfigStreamEvent, error) {
	payload, err := json.Marshal(m)
	if err != nil {
		return ConfigStreamEvent{}, err
	}
	return ConfigStreamEvent{
		Type:      EventMirrorUpsert,
		Data:      payload,
		Timestamp: time.Now().UTC(),
	}, nil
}

// NewMirrorDeleteEvent encodes a mirror deregister delta.
func NewMirrorDeleteEvent(host string) (ConfigStreamEvent, error) {
	payload, err := json.Marshal(MirrorDeletePayload{Host: host})
	if err != nil {
		return ConfigStreamEvent{}, err
	}
	return ConfigStreamEvent{
		Type:      EventMirrorDelete,
		Data:      payload,
		Timestamp: time.Now().UTC(),
	}, nil
}
