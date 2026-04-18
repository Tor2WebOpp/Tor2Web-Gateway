// Package headers implements the "proxy_headers" feature: per-tenant
// templated request and response header rewriting.
//
// Four operation lists are supported, applied in order:
//
//   - strip_upstream   — header names removed from the request before the
//     proxy forwards it to the backend.
//   - add_upstream     — headers added to the request (templated values,
//     see below). A header with the same name is replaced wholesale
//     so that the backend never sees a stale upstream value.
//   - strip_downstream — header names removed from the response returned
//     to the client.
//   - add_downstream   — headers added to the response (templated values).
//     Same replace-wholesale semantics as add_upstream.
//
// Header values in the add_* lists may contain the following expansions:
//
//   - {{client_ip}}    — the client IP extracted from the request's
//     RemoteAddr (the port, when present, is stripped).
//   - {{tenant_host}}  — the tenant host stashed on the request context by
//     the routing layer; empty when no tenant is bound.
//   - {{request_id}}   — an opaque per-invocation token, regenerated on
//     each Render call using crypto/rand so two adjacent requests never
//     produce the same value.
//   - {{now_rfc3339}}  — the current wall-clock time formatted per RFC
//     3339 (seconds precision, UTC).
//   - {{header:Name}}  — the first value of the named request header at
//     the moment of rendering. Empty when the header is absent.
//
// Templates are parsed and type-checked during Validate so that reloads
// containing an unknown variable are rejected before any state is swapped.
// The parsed representation is cached per tenant in Observe, so the hot
// path only performs variable lookups — no parsing, no allocation of parse
// trees, no map of operations per request.
//
// Request mutation happens before the handler is passed further down the
// chain. Response mutation is implemented with a small ResponseWriter
// wrapper that intercepts WriteHeader and applies strip_downstream /
// add_downstream before any headers are flushed to the client.
package headers
