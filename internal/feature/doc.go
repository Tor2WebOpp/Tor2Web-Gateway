// Package feature provides a pluggable feature registry and toggle
// resolution for the gateway HTTP pipeline.
//
// Each capability implements the Feature interface and is registered with
// a Registry at startup. The registry composes every feature into a single
// middleware chain in registration order; disabled features short-circuit
// to pass-through without allocations and without map lookups per request.
//
// Toggle state is provided by a Resolver that reads the tenant attached to
// the request context and applies precedence: tenant override, then
// globals, then a zero (disabled) fallback. Reloads validate all features
// against all tenants before any state is swapped, so configuration errors
// never corrupt the live pipeline.
package feature
