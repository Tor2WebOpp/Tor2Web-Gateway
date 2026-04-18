// Package ratelimit implements the "rate_limit" feature: per-tenant token
// buckets that enforce per-IP, global, and API-path-specific request rate
// limits.
//
// Buckets are keyed by the pair (tenant.Host, client_ip) for per-IP limits.
// A global limiter and a per-API-path limiter live once per tenant. Disabled
// tenants incur no middleware work beyond an atomic load and a context read.
//
// The feature reuses the logic of internal/proxy/ratelimit.go (the pre-P1
// single-tenant implementation) but generalises it so configuration is
// supplied by the feature registry (per reload) and isolation is enforced
// per tenant. A single shared background goroutine sweeps stale per-IP
// buckets across all tenants on cleanup_interval_seconds.
//
// Actions on exceed:
//
//   - "429" (default) — writes 429 Too Many Requests with a Retry-After
//     header and ends the request.
//   - "drop"          — hijacks the underlying connection and closes it
//     silently. Falls back to 400 when hijack is not
//     available.
//   - "timeout"       — blocks the handler for the configured cleanup
//     interval (or 30s when not set) and then writes 408.
//
// Configuration is sourced from shared.FeatureSnapshot.Params; unknown keys
// are ignored and absent keys fall back to safe defaults listed in params.
package ratelimit
