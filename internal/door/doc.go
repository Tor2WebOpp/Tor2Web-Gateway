// Package door implements the gateway-door node: a lightweight HTTP
// surface whose only two behaviours are
//
//   - presenting a benign cover page at "/",
//   - redirecting "/<slug>..." to a currently-healthy mirror domain.
//
// The door is deliberately minimal. It does not run the Tor pool, does
// not hold tenant state, does not consult the feature registry, and
// never emits logs at INFO level that name the mirror it picked (DEBUG
// only). Its job is to look like a stale, uninteresting nginx default
// so casual scanners move on; the slug-keyed redirect is only apparent
// to operators who already know the slug.
//
// Core components:
//
//   - CoverHandler serves "/" — either a static file, an inline HTML
//     snippet loaded from disk, or a default-looking 404 that mimics an
//     un-configured nginx server.
//   - RedirectHandler matches the first path segment against the
//     configured slugs in constant time (re-using the admin gate's
//     pad-and-ConstantTimeCompare pattern) and on match picks a live
//     mirror via Selector.
//   - Selector owns the in-memory mirror-health table. It is fed by
//     SnapshotClient which subscribes to the hub's /v1/config/stream
//     and translates mirror_snapshot / mirror_upsert / mirror_delete
//     events into UpdateMirrors / UpsertMirror / RemoveMirror calls.
//   - Server composes the three handlers with the admin.Gate so that
//     gate paths remain invisible (the same constant-time carve-out
//     applies on doors as on proxies).
//
// Threading: every handler is safe for concurrent use. Hot reloads
// (slug add/remove, mirror-table refresh) take a short write lock and
// swap a pointer; requests in flight continue to see the previous
// state.
package door
