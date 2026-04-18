// Package staticcache implements the "static_cache" feature: a response
// cache for static assets keyed by the requesting tenant, request method
// and URL path.
//
// The cache is a thin wrapper around a single process-wide Ristretto v2
// store, sized by the global max_size_mb parameter. Per-tenant caps are
// supported via the per_tenant_size_fraction parameter: when greater than
// zero, the reported cost for entries of that tenant is scaled up so that
// Ristretto's admission policy refuses to let a single tenant hold more
// than its fractional share of the cache. Fraction 0 (the default)
// disables the cap and lets tenants share the entire cache pool.
//
// Cache keys are sha256(tenant_host + "|" + method + "|" + url.Path).
// Including the tenant in the key is load-bearing: two tenants may serve
// different bytes on the same path, and mixing entries would constitute
// cross-tenant cache poisoning. Missing tenant context is handled by a
// "_global_" sentinel so that the package works in unit tests and in
// flows that predate tenant routing.
//
// Only safely cacheable responses are stored:
//
//   - Status codes in 200..299.
//   - Content-Length header present (streamed/unknown-length responses
//     are passed through unchanged).
//   - Request path ends in a configured static extension.
//   - Request method is GET or HEAD.
//   - Response Content-Type, if set, is whitelisted for the matching
//     extension family (text/css, application/javascript, image/*,
//     font/*, application/font-woff2, image/svg+xml, image/webp).
//
// On a miss, the handler's response is buffered in memory up to the
// global max body size (5 MiB), stored with the configured TTL, and then
// flushed to the client verbatim. On a hit, the cached status code,
// headers and body are written directly and the downstream handler is
// not invoked.
//
// Reload semantics:
//
//   - Changing max_size_mb rebuilds the underlying Ristretto store. All
//     prior entries are discarded.
//   - Changing static_extensions rebuilds the store as well, on the
//     conservative assumption that extension churn may invalidate many
//     entries and it is simpler to drop everything than to enumerate.
//   - Changing only default_ttl or per_tenant_size_fraction keeps the
//     existing store: new writes honour the new TTL and cost, older
//     entries live out their original TTL.
//
// The feature is concurrency-safe. The hot path reads an atomic enabled
// flag and an atomic pointer to the active parameter block; reloads
// acquire a write lock only to swap pointers. Cache stampedes on the
// same key are tolerated — every concurrent miss runs the backend
// handler and attempts to populate the cache. This is explicitly
// acceptable per the P1 spec; upgrading to singleflight is an
// implementation detail that can land without an API change.
package staticcache
