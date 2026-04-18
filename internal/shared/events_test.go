package shared

import (
	"encoding/json"
	"testing"
	"time"
)

func TestConfigStreamEvent_Snapshot(t *testing.T) {
	before := time.Now().UTC().Add(-time.Second)
	tenants := []TenantInfo{{Host: "a.tld", Enabled: true, Version: 1}}
	globals := json.RawMessage(`{"features":{}}`)
	ev, err := NewSnapshotEvent(tenants, globals, 5)
	if err != nil {
		t.Fatalf("NewSnapshotEvent: %v", err)
	}
	if ev.Type != EventSnapshot {
		t.Fatalf("type = %q", ev.Type)
	}
	if ev.Timestamp.Before(before) {
		t.Fatalf("timestamp not set: %v", ev.Timestamp)
	}
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out ConfigStreamEvent
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Type != EventSnapshot {
		t.Fatalf("roundtrip type = %q", out.Type)
	}
	var payload SnapshotPayload
	if err := json.Unmarshal(out.Data, &payload); err != nil {
		t.Fatalf("payload unmarshal: %v", err)
	}
	if len(payload.Tenants) != 1 || payload.Tenants[0].Host != "a.tld" || payload.Version != 5 {
		t.Fatalf("payload mismatch: %+v", payload)
	}
}

func TestConfigStreamEvent_TenantUpsert(t *testing.T) {
	before := time.Now().UTC().Add(-time.Second)
	in := TenantInfo{Host: "b.tld", Enabled: true, Version: 9}
	ev, err := NewTenantUpsertEvent(in)
	if err != nil {
		t.Fatalf("NewTenantUpsertEvent: %v", err)
	}
	if ev.Type != EventTenantUpsert {
		t.Fatalf("type = %q", ev.Type)
	}
	if ev.Timestamp.Before(before) {
		t.Fatalf("timestamp not set: %v", ev.Timestamp)
	}
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out ConfigStreamEvent
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var got TenantInfo
	if err := json.Unmarshal(out.Data, &got); err != nil {
		t.Fatalf("payload unmarshal: %v", err)
	}
	if got.Host != in.Host || got.Version != in.Version {
		t.Fatalf("tenant roundtrip mismatch: %+v", got)
	}
}

func TestConfigStreamEvent_TenantDelete(t *testing.T) {
	before := time.Now().UTC().Add(-time.Second)
	ev, err := NewTenantDeleteEvent("gone.tld")
	if err != nil {
		t.Fatalf("NewTenantDeleteEvent: %v", err)
	}
	if ev.Type != EventTenantDelete {
		t.Fatalf("type = %q", ev.Type)
	}
	if ev.Timestamp.Before(before) {
		t.Fatalf("timestamp not set: %v", ev.Timestamp)
	}
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out ConfigStreamEvent
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var payload TenantDeletePayload
	if err := json.Unmarshal(out.Data, &payload); err != nil {
		t.Fatalf("payload unmarshal: %v", err)
	}
	if payload.Host != "gone.tld" {
		t.Fatalf("host mismatch: %q", payload.Host)
	}
}

func TestConfigStreamEvent_GlobalsUpdate(t *testing.T) {
	before := time.Now().UTC().Add(-time.Second)
	globals := json.RawMessage(`{"features":{"rate_limit":{"enabled":true}}}`)
	ev := NewGlobalsEvent(globals)
	if ev.Type != EventGlobalsUpdate {
		t.Fatalf("type = %q", ev.Type)
	}
	if ev.Timestamp.Before(before) {
		t.Fatalf("timestamp not set: %v", ev.Timestamp)
	}
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out ConfigStreamEvent
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(out.Data) != string(globals) {
		t.Fatalf("globals payload mismatch: %s", out.Data)
	}
}
