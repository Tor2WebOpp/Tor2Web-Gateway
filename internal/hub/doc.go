// Package hub implements the tenant registry that lives on the gateway-hub
// node. It is the authoritative in-memory + on-disk store for runtime Layer 2
// configuration: per-tenant YAML under <data_dir>/tenants/ plus a single
// globals.yaml.
//
// Registry is goroutine-safe. Writes (Upsert, Delete, SetGlobals) are
// serialised under a RWMutex, first persisted atomically to disk via Storage,
// then applied to the in-memory maps, then broadcast to subscribers as a
// shared.ConfigStreamEvent. Subscribers receive events in the order they were
// broadcast; if a subscriber's bounded channel fills up, the oldest buffered
// event for that subscriber is dropped so slow consumers cannot stall the hub.
//
// Storage writes are atomic: tmp file + rename. Storage.Watch uses fsnotify
// to observe out-of-band edits to the tenants/ directory and globals.yaml,
// debounced so batch edits (e.g. a text-editor's write+rename) produce one
// reload. When Registry sees its own change come back through the watcher
// the reload is idempotent and subscribers receive the snapshot delta.
//
// This package does no HTTP, no SOCKS, no auth. Those layers are built on
// top of Registry in later waves.
package hub
