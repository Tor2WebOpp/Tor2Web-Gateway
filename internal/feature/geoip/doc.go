// Package geoip implements the "geoip" feature: per-tenant country-based
// blocking backed by a MaxMind GeoLite2-Country database.
//
// The feature resolves a client IP from the request (either RemoteAddr or
// the last value of X-Forwarded-For when trust_xff is enabled), looks it up
// in an open *maxminddb.Reader to obtain the ISO 3166-1 alpha-2 country
// code, and — when that code appears in the tenant's block_countries list —
// applies one of the configured block actions: drop, 404, 429, or timeout.
//
// Reader lifecycle is refcounted by db_path. Observe recomputes the set of
// paths referenced by the current globals+tenants snapshot; new paths are
// opened exactly once, paths no longer referenced are closed. A single
// *maxminddb.Reader is shared by every tenant that names the same db_path
// so that process-wide there is one mmap per file on disk.
//
// The hot path first checks an atomic.Bool guard (set by Observe whenever
// the feature is enabled for at least one tenant or globally), then
// consults the Resolver for per-request config, then performs the lookup.
// When the guard is false the middleware collapses to a pass-through that
// allocates nothing and takes no locks.
//
// Testing uses a LookupFunc injection point so unit tests do not need a
// real .mmdb file on disk — production code wraps *maxminddb.Reader.Lookup
// with the same signature.
package geoip
