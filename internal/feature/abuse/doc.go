// Package abuse implements the "abuse_api" feature: a tenant-configurable
// endpoint that accepts abuse reports via HTTP POST and persists them to
// an append-only JSONL file.
//
// Configuration is sourced from shared.FeatureSnapshot.Params:
//
//   - path                 — exact path the endpoint matches (default "/_abuse")
//   - store_path           — filesystem path to the append-only JSONL log
//   - notify_email         — reserved; null in P1 (store only)
//   - rate_limit_per_hour  — per-(tenant, client_ip_hash) request ceiling over
//     a rolling 1h window (default 10)
//   - require_fields       — report fields that must be non-empty; default
//     ["onion", "reason"]
//
// Endpoint behaviour:
//
//   - POST /_abuse (or configured path) with JSON body
//     {onion, reason, contact?, details?} → 204 No Content on success.
//   - GET or any other method on the configured path → 405.
//   - Validation failure → 400 with a fixed generic message; request
//     contents are never echoed.
//   - Rate-limit exceeded → 429 with Retry-After header.
//   - Feature disabled → pass-through (endpoint effectively nonexistent,
//     reaches the downstream 404).
//
// OPSEC notes:
//   - The client IP is never logged or stored in raw form. It is hashed
//     with a server-side salt (sha256(ip + salt)) before use as a
//     rate-limit key or record field.
//   - Responses carry a fixed, minimal header set and expose no Server
//     header or other metadata.
//   - The store file is opened append-only with mode 0600.
package abuse
