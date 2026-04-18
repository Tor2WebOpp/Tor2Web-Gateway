# Hub API reference

The hub exposes a small JSON API for tenant administration, node registration, and torpool control. This document lists every endpoint with auth, request, and response shapes, plus `curl` examples. All examples assume the hub is reachable at `https://10.0.0.1:9080` over WireGuard. For the `https_tunnel` and `socks5_tls` transports substitute the appropriate URL and admin port.

## Auth model

Every request to the hub requires mTLS with a client certificate signed by the hub CA. The CA is generated at hub install time and lives in `/etc/gateway/hub-ca.key` on the hub. Client certificates are of two kinds:

- Edge certificates. CN is the `node_id` from the edge's bootstrap config. Issued by the hub in response to `POST /v1/nodes/register`. Edges use these certs to fetch config and reach the torpool.
- Admin certificates. CN is any operator-chosen identifier. Issued by the hub installer and stored on whichever machine the operator runs `curl` from. Admin certs can call every endpoint; edge certs can only call torpool and config-stream endpoints.

There is no token-based auth in P1. There are no API keys. The client cert is the whole authentication surface.

Authorization check:

- If the CN corresponds to a registered edge, the caller is treated as an edge and is restricted to: `GET /v1/config/stream`, `GET /v1/backends`, `GET /v1/health`, and `POST /v1/nodes/register` (idempotent re-registration).
- If the certificate's CN is not in the edge registry, the caller is treated as admin and can call every endpoint.
- Unknown or revoked certificates are rejected at the TLS layer.

The CRL is reloaded every 60 seconds from `/var/lib/gateway/hub/crl.pem`. Revoking a cert via the admin API writes to the CRL file and takes effect on the next reload.

## Content type

All request and response bodies are `application/json` unless otherwise noted. The one exception is `PUT /v1/tenants/<host>`, which accepts `application/yaml` for direct upload of tenant files.

Timestamps are RFC 3339 UTC (`2026-04-18T10:00:00Z`).

Errors follow one shape:

```json
{
  "error": "tenant_not_found",
  "message": "no tenant with host example.your-domain.example",
  "details": {}
}
```

The `error` field is a short stable code suitable for programmatic matching. `message` is human-readable and may change. `details` is an object with feature-specific context; fields vary per error code.

HTTP status codes follow the usual semantics: 200 for success, 201 for resource creation, 204 for deletions, 400 for validation errors, 401 for missing or invalid client cert (rare; TLS rejects most of these earlier), 403 for edge caller reaching an admin-only endpoint, 404 for missing resource, 409 for conflicts, 500 for internal errors.

## Tenant endpoints

### List tenants

`GET /v1/tenants`

Response:

```json
{
  "tenants": [
    {
      "host": "example.your-domain.example",
      "enabled": true,
      "backends": [
        { "addr": "aaaa...56chars...aaaa.onion", "weight": 1 }
      ],
      "assigned_nodes": "*",
      "updated_at": "2026-04-18T10:00:00Z"
    }
  ],
  "count": 1
}
```

The response only includes top-level tenant fields. To fetch the full feature configuration for a tenant, use the GET-by-host endpoint.

Example:

```bash
curl -sS \
  --cert /etc/gateway/admin.crt \
  --key  /etc/gateway/admin.key \
  --cacert /etc/gateway/hub-ca.crt \
  https://10.0.0.1:9080/v1/tenants | jq
```

### Get a tenant

`GET /v1/tenants/<host>`

Returns the full parsed tenant struct including every feature override.

```bash
curl -sS \
  --cert /etc/gateway/admin.crt --key /etc/gateway/admin.key \
  --cacert /etc/gateway/hub-ca.crt \
  https://10.0.0.1:9080/v1/tenants/example.your-domain.example | jq
```

Response shape: the full tenant YAML parsed to JSON. See `tenants.md` for the schema.

### Create or update a tenant

`PUT /v1/tenants/<host>`

Accepts either JSON or YAML. The body must parse to a valid tenant struct; `host` inside the body must match the `<host>` in the path.

```bash
curl -sS \
  --cert /etc/gateway/admin.crt --key /etc/gateway/admin.key \
  --cacert /etc/gateway/hub-ca.crt \
  -X PUT \
  -H 'Content-Type: application/yaml' \
  --data-binary @example.yaml \
  https://10.0.0.1:9080/v1/tenants/example.your-domain.example
```

On success, returns 200 (update) or 201 (create) with the parsed tenant. On validation error, returns 400 with:

```json
{
  "error": "tenant_invalid",
  "message": "backend 0: not a valid v3 onion address",
  "details": { "field": "backends[0].addr", "value": "abc.onion" }
}
```

The hub writes the tenant file to `runtime/tenants/<host>.yaml` atomically; `fsnotify` then triggers the registry reload.

### Delete a tenant

`DELETE /v1/tenants/<host>`

Soft-deletes the tenant. Returns 204 on success.

```bash
curl -sS \
  --cert /etc/gateway/admin.crt --key /etc/gateway/admin.key \
  --cacert /etc/gateway/hub-ca.crt \
  -X DELETE \
  https://10.0.0.1:9080/v1/tenants/example.your-domain.example
```

The tenant is marked `deleted_at: <now>` in memory and the file is renamed to `runtime/tenants/<host>.yaml.deleted-<timestamp>`. Requests during the grace window (60 seconds) receive HTTP 410 Gone from the edge. After the grace window, the tenant is removed from the registry.

Restoring a tenant before the grace window ends is done by posting the old file back via PUT; the hub detects the matching `deleted_at` and resurrects the entry.

## Globals endpoint

### Get globals

`GET /v1/globals`

Returns `globals.yaml` parsed to JSON.

### Update globals

`PUT /v1/globals`

Accepts JSON or YAML. Validation runs across every registered tenant; a globals change that would invalidate any tenant is rejected. The error response includes the specific tenant and field.

```bash
curl -sS \
  --cert /etc/gateway/admin.crt --key /etc/gateway/admin.key \
  --cacert /etc/gateway/hub-ca.crt \
  -X PUT \
  -H 'Content-Type: application/yaml' \
  --data-binary @globals.yaml \
  https://10.0.0.1:9080/v1/globals
```

## Node (edge) endpoints

### Register a node

`POST /v1/nodes/register`

The edge's installer calls this once during setup. The request body includes the node's identity, the node-secret from bootstrap for initial trust, and a CSR. The response is a signed client certificate.

Request:

```json
{
  "node_id": "edge-7a3c",
  "node_type": "proxy",
  "node_secret": "<hex from /etc/gateway/node-secret>",
  "public_key": "<wg public key, present only when transport is wireguard>",
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n..."
}
```

Response:

```json
{
  "node_id": "edge-7a3c",
  "client_cert_pem": "-----BEGIN CERTIFICATE-----\n...",
  "ca_chain_pem": "-----BEGIN CERTIFICATE-----\n...",
  "wg_server_pubkey": "<hub wg pubkey>",
  "wg_allocated_ip": "10.0.0.42/32",
  "registered_at": "2026-04-18T10:00:00Z"
}
```

Re-registration with the same `node_id` and a matching node-secret is idempotent: it reissues a client cert for a fresh CSR but keeps the wg allocation stable. Mismatched node-secret returns 403.

### List nodes

`GET /v1/nodes`

```json
{
  "nodes": [
    {
      "node_id": "edge-7a3c",
      "node_type": "proxy",
      "wg_allocated_ip": "10.0.0.42/32",
      "cert_not_after": "2027-04-18T10:00:00Z",
      "last_seen": "2026-04-18T10:05:12Z",
      "revoked": false
    }
  ],
  "count": 1
}
```

### Revoke a node

`DELETE /v1/nodes/<id>`

Adds the node's client certificate serial to the CRL. The CRL is reloaded every 60 seconds; revocation takes effect by the next reload. The node's config stream closes on the next heartbeat; if the node does not close new connections within `grace_seconds` (30), operators should assume its traffic may briefly continue and rely on TLS-level rejection after the grace window.

```bash
curl -sS \
  --cert /etc/gateway/admin.crt --key /etc/gateway/admin.key \
  --cacert /etc/gateway/hub-ca.crt \
  -X DELETE \
  https://10.0.0.1:9080/v1/nodes/edge-7a3c
```

## Config stream

### Subscribe to config updates

`GET /v1/config/stream?node_id=<id>`

Long-poll. The first response is a full snapshot of tenants and globals scoped to what this node is allowed to serve. Subsequent requests block until a change occurs, then return the delta. The server writes a `Last-Event-ID` header on every response; the client includes it as `Last-Event-ID` on the next request so the hub only returns events newer than that.

The connection is kept alive with an empty event every 25 seconds to defeat intermediate idle timeouts.

Snapshot payload:

```json
{
  "event_id": "42",
  "kind": "snapshot",
  "globals": { ... },
  "tenants": [ ... ]
}
```

Delta payload:

```json
{
  "event_id": "43",
  "kind": "delta",
  "tenants_updated": [ { "host": "example.your-domain.example", ... } ],
  "tenants_removed": [ "old.your-domain.example" ],
  "globals": null
}
```

`globals` on a delta is either null (no change) or the full globals struct (change). Edges treat the full struct as an atomic replacement.

Edges reconnect on disconnect with exponential backoff capped at 30 seconds.

## Torpool endpoints

These endpoints proxy through to the internal `gateway-torpool` API so that edges can call them without holding a direct socket to the torpool.

### List backends

`GET /v1/backends`

```json
{
  "backends": [
    {
      "port": 9050,
      "healthy": true,
      "active_conns": 3,
      "latency_ms": 420,
      "error_rate": 0.02,
      "circuit_state": "closed"
    }
  ],
  "updated_at": "2026-04-18T10:00:00Z"
}
```

Callable by edge certs.

### Pool health

`GET /v1/health`

```json
{
  "instances_total": 6,
  "instances_healthy": 5,
  "instances_cold": 1,
  "pool_busy_fraction": 0.43,
  "last_scale_event": {
    "at": "2026-04-18T09:58:12Z",
    "direction": "up",
    "from": 5,
    "to": 6
  }
}
```

Callable by edge certs.

### Force scale

`POST /v1/scale`

Admin-only. Sets min/max temporarily. The pool reverts to the configured values on hub restart.

```json
{
  "min_instances": 8,
  "max_instances": 16
}
```

Response is the same shape. 400 on invalid values (min > max, min < 1, max > hard limit).

## Mirror endpoints

These endpoints manage the P2 mirror-health registry. A mirror is a public hostname that fronts one or more tenants; the registry tracks its reachability across operator-chosen regions. For the underlying data model and the verdict rules see `mirrors.md`.

### List mirrors

`GET /v1/mirrors`

Admin-only. Returns every registered mirror with its current verdict and the latest per-region status map.

```json
{
  "mirrors": [
    {
      "host": "mirror-3.your-domain.example",
      "tenants": ["example.your-domain.example"],
      "weight": 1,
      "verdict": "live",
      "last_check": "2026-04-18T10:00:00Z",
      "manual_block": false,
      "manual_note": "",
      "regions": {
        "us1": { "status": "ok",      "latency": 180, "at": "2026-04-18T10:00:00Z" },
        "de1": { "status": "ok",      "latency": 220, "at": "2026-04-18T10:00:00Z" },
        "ru1": { "status": "refused", "latency": 0,   "at": "2026-04-18T10:00:00Z" }
      }
    }
  ],
  "count": 1
}
```

### Get one mirror

`GET /v1/mirrors/<host>`

Same shape as one entry from the list response. 404 if the host is not registered.

### Register or update a mirror

`PUT /v1/mirrors/<host>`

Accepts JSON or YAML. The body must parse to a valid mirror record; derived fields (`verdict`, `last_check`, `regions`, counters) are ignored in the request and filled in by the hub.

```bash
curl -sS \
  --cert /etc/gateway/admin.crt --key /etc/gateway/admin.key \
  --cacert /etc/gateway/hub-ca.crt \
  -X PUT \
  -H 'Content-Type: application/yaml' \
  --data-binary @mirror.yaml \
  https://10.0.0.1:9080/v1/mirrors/mirror-3.your-domain.example
```

200 on update, 201 on create, 400 on validation error. Validation rules: `host` must be a valid DNS name, `tenants` entries must exist in the tenant registry, `weight` must be a non-negative integer.

### Deregister a mirror

`DELETE /v1/mirrors/<host>`

Removes the mirror. Returns 204. Doors that reference the mirror through a slug continue to operate; the mirror simply drops out of the selection set.

### Force-block a mirror

`POST /v1/mirrors/<host>/force-block`

Admin-only. Sets `manual_block: true` and records the note. The verdict becomes `blocked` regardless of health data.

```bash
curl -sS \
  --cert /etc/gateway/admin.crt --key /etc/gateway/admin.key \
  --cacert /etc/gateway/hub-ca.crt \
  -X POST \
  -d '{"note":"Provider complaint ticket 12345"}' \
  https://10.0.0.1:9080/v1/mirrors/mirror-3.your-domain.example/force-block
```

### Unblock a mirror

`POST /v1/mirrors/<host>/unblock`

Clears `manual_block`. The verdict reverts to whatever the health data says on the next recomputation.

### Trigger an immediate check

`POST /v1/mirrors/check`

Admin-only. Runs a check-host.net pass against every registered mirror immediately rather than waiting for the next scheduled interval.

```bash
curl -sS \
  --cert /etc/gateway/admin.crt --key /etc/gateway/admin.key \
  --cacert /etc/gateway/hub-ca.crt \
  -X POST \
  -d '{"regions":["us1","de1","nl1"]}' \
  https://10.0.0.1:9080/v1/mirrors/check
```

Body is optional. When omitted, the regions configured under `/v1/settings/checkhost` are used. Rate-limited to one invocation per 60 seconds across all callers.

## check-host settings

### Get check-host settings

`GET /v1/settings/checkhost`

```json
{
  "enabled": true,
  "interval": "15m",
  "regions": ["us1", "de1", "nl1", "ru1"],
  "threshold_pct": 50,
  "max_nodes": 4,
  "min_request_spacing": "5s",
  "block_patterns": []
}
```

### Update check-host settings

`PUT /v1/settings/checkhost`

Accepts JSON. Every field is optional; only the fields present in the body are updated.

```bash
curl -sS \
  --cert /etc/gateway/admin.crt --key /etc/gateway/admin.key \
  --cacert /etc/gateway/hub-ca.crt \
  -X PUT \
  -H 'Content-Type: application/json' \
  -d '{"enabled":true,"interval":"15m","regions":["us1","de1","ru1"],"threshold_pct":50}' \
  https://10.0.0.1:9080/v1/settings/checkhost
```

Validation rules: `interval` parses as a Go duration and is at least 1 minute. `threshold_pct` is between 1 and 100. `regions` entries must be non-empty strings. `max_nodes` is between 1 and 16. `block_patterns` entries must compile as Go regex.

## Door slug endpoints

### List slugs for a door

`GET /v1/doors/<node_id>/slugs`

Admin-only. Returns the current slug list for a specific door.

```json
{
  "slugs": [
    {
      "slug": "EXAMPLE-SLUG",
      "strategy": "random",
      "status": 302,
      "target_tenants": [],
      "exclude_regions": []
    }
  ],
  "count": 1
}
```

### Create a slug

`POST /v1/doors/<node_id>/slugs`

```bash
curl -sS \
  --cert /etc/gateway/admin.crt --key /etc/gateway/admin.key \
  --cacert /etc/gateway/hub-ca.crt \
  -X POST \
  -H 'Content-Type: application/json' \
  -d '{"slug":"EXAMPLE-SLUG","strategy":"random","status":302}' \
  https://10.0.0.1:9080/v1/doors/door-01/slugs
```

The slug string must be 32 characters. The hub generates one if the caller omits the field.

### Rotate a slug

`POST /v1/doors/<node_id>/slugs/rotate`

Creates a fresh slug and keeps the old one live for `grace_seconds`. Body:

```json
{ "old": "EXAMPLE-SLUG", "grace_seconds": 300 }
```

Returns the new slug in the response.

### Delete a slug

`DELETE /v1/doors/<node_id>/slugs/<slug>`

Removes the slug from the door's runtime. 204 on success.

## Abuse reports

### List reports

`GET /v1/abuse?tenant=<host>&since=<rfc3339>`

Admin-only. Returns abuse reports received on the tenant's `/_abuse` endpoint. `tenant` is optional (omitted = all tenants). `since` is optional (omitted = last 7 days).

```json
{
  "reports": [
    {
      "id": "rep_01HX...",
      "tenant_host": "example.your-domain.example",
      "received_at": "2026-04-18T09:00:00Z",
      "client_ip_hash": "sha256-hex",
      "body": {
        "onion": "aaaa...aaaa.onion",
        "reason": "phishing",
        "contact": "reporter@example"
      }
    }
  ],
  "count": 1
}
```

`client_ip_hash` is `sha256(client_ip + metrics_salt)[:16]`, never the raw IP.

## Admin gate carve-out (P1 stub)

`* /<slug>/<token1>/<token2>/**`

In P1 any path matching this prefix returns HTTP 501 with body `{"error":"not_implemented"}`. The match uses constant-time comparison regardless of outcome. The matching paths are not logged. P3 will fill the handler with the real admin surface.

Do not use this in P1 for anything. Configure a routing rule in your fronting proxy that drops requests for this prefix entirely if you want to hide it from the public internet.

## curl template

For every admin call, the minimum set of flags is:

```bash
curl -sS \
  --cert /etc/gateway/admin.crt \
  --key  /etc/gateway/admin.key \
  --cacert /etc/gateway/hub-ca.crt \
  <method and URL>
```

Edge self-check (torpool health) from an edge:

```bash
curl -sS \
  --cert /etc/gateway/client.crt \
  --key  /etc/gateway/client.key \
  --cacert /etc/gateway/hub-ca.crt \
  https://10.0.0.1:9080/v1/health
```

Store these commands behind a shell alias to reduce typing; never embed cert contents in scripts or environment variables.

## Rate limits on the admin API

The admin API itself is not rate-limited in P1 beyond the TLS handshake cost. P3 will add per-CN rate limits and lockout on repeated validation failures. Until then, treat the admin API as an internal-use interface on a private network (wg or otherwise) and do not expose it to the public internet.

## Error codes

| Code | HTTP | Meaning |
|---|---|---|
| `tenant_not_found` | 404 | No tenant with the given host. |
| `tenant_invalid` | 400 | Request body failed validation. `details.field` and `details.value` identify the issue. |
| `tenant_conflict` | 409 | The host inside the body does not match the path. |
| `onion_invalid` | 400 | A backend is not a valid v3 onion address. |
| `feature_invalid` | 400 | A feature config failed validation. `details.feature` names it. |
| `globals_invalid` | 400 | Globals change would invalidate one or more tenants. `details.tenants` lists them. |
| `node_not_found` | 404 | No node with the given id. |
| `node_conflict` | 409 | Node already registered with different node_type or public_key. |
| `mirror_not_found` | 404 | No mirror with the given host. |
| `mirror_invalid` | 400 | Request body failed validation. `details.field` names the issue. |
| `checkhost_invalid` | 400 | Settings payload failed validation. `details.field` names it. |
| `checkhost_ratelimited` | 429 | Manual check triggered within 60 seconds of the last invocation. |
| `slug_not_found` | 404 | No slug with the given value for this door. |
| `slug_invalid` | 400 | Slug length, strategy, or status is not accepted. |
| `not_implemented` | 501 | Admin gate in P1; not an error per se. |
| `forbidden` | 403 | Edge cert tried to reach admin-only endpoint. |
| `internal` | 500 | Unhandled server error. Check hub logs. |
