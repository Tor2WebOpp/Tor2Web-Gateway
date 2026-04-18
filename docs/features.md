# Feature reference

Every feature in the gateway is configured at two layers. `globals.yaml` sets the defaults. `tenants/<host>.yaml` can override any feature or any single field within a feature. Disabled features are bypassed in the middleware chain before they enter it, so the cost of a disabled feature at runtime is zero.

This document lists every P1 feature with its purpose, configuration fields, defaults, and a per-tenant override example. For the layout of tenant files see `tenants.md`.

## Resolution order

Every request resolves feature configuration in three steps:

1. Tenant override, if `tenants/<host>.yaml` sets `features.<name>`.
2. Global default, from `globals.yaml` `features.<name>`.
3. Hardcoded safe default (feature disabled, zero values) if neither of the above is set.

Setting `enabled: false` at the tenant level disables the feature for that tenant even if globals enables it. Setting `enabled: true` with no parameters uses global parameters with the feature switched on.

## blocklist_regex

Compiled regex patterns matched against the request path and headers. Matches trigger a configurable action.

Fields:

- `enabled` (bool, default false) — turn the feature on.
- `default_action` (string, default `drop`) — action when a pattern in globals matches; one of `drop`, `404`, `429`, `timeout`.
- `patterns` ([]object) — list of pattern/action pairs. Each item:
  - `pattern` (string, required) — Go `regexp/syntax` pattern. Compiled once at load time.
  - `match` (string, default `path`) — `path` | `header:<Name>` | `path_or_header:<Name>`.
  - `action` (string, default = `default_action`) — per-pattern override of the action.

Global default in P1: enabled, with no patterns. A tenant that enables the feature without providing patterns inherits the empty global list, which matches nothing.

Tenant override example:

```yaml
features:
  blocklist_regex:
    enabled: true
    patterns:
      - pattern: "(?i)wp-(login|admin)"
        action: 404
      - pattern: "\\.env$"
        action: drop
      - pattern: "^/xmlrpc\\.php"
        action: 429
      - pattern: "(?i)sqlmap|nikto|nmap"
        match: "header:User-Agent"
        action: drop
```

Limits: 256 patterns per tenant, 512 characters per pattern.

## geoip

MaxMind GeoLite2-Country lookup on the client IP. Countries in the block list trigger the configured action.

Fields:

- `enabled` (bool, default false).
- `db_path` (string, bootstrap) — the MaxMind `.mmdb` file. Set once in the bootstrap config under `features.geoip.db_path`; not per-tenant. If the file is missing, the feature refuses to start on reload.
- `block_countries` ([]string) — ISO 3166-1 alpha-2 country codes, uppercase.
- `allow_countries` ([]string) — if set, only these countries are allowed; `block_countries` is ignored.
- `action` (string, default `404`) — one of `drop`, `404`, `429`, `timeout`.
- `trust_xff` (bool, default false) — when true, the feature reads the client IP from the first entry in `X-Forwarded-For`. Only enable when the edge sits behind a trusted frontend (e.g. Cloudflare) that rewrites XFF.

Global default in P1: disabled. The bootstrap `db_path` is read once at hub start.

Tenant override example:

```yaml
features:
  geoip:
    enabled: true
    block_countries: [CN, IR, RU, KP]
    action: 404
    trust_xff: true
```

Limits: 256 entries across `block_countries` and `allow_countries` combined.

## rate_limit

Token-bucket per client IP, per tenant. Separate buckets per tenant mean a noisy tenant cannot exhaust another tenant's allowance.

Fields:

- `enabled` (bool, default true).
- `per_ip_rps` (int, default 10) — sustained requests per second per client IP.
- `per_ip_burst` (int, default 20) — burst allowance per client IP.
- `per_ip_conns` (int, default 50) — max simultaneous connections per client IP. 0 disables this check.
- `global_rps` (int, default 0) — tenant-wide RPS cap across all clients. 0 disables.
- `cleanup_interval` (duration, default `5m`) — how often the limiter purges stale per-IP buckets.
- `action` (string, default `429`) — `drop`, `404`, `429`, `timeout`.

Global default in P1: enabled, 10 rps / 20 burst, no global cap.

Tenant override example:

```yaml
features:
  rate_limit:
    enabled: true
    per_ip_rps: 3
    per_ip_burst: 6
    global_rps: 200
```

Limits: per_ip_rps and global_rps must be between 0 and 10000.

## ttl_blocklist

Persistent blocklist keyed by client IP with time-to-live. Entries can be written by the regex blocker, by rate-limit exhaustion (after N consecutive triggers), or via the admin API. Backed by a BoltDB file set in the bootstrap config (`features.ttl_blocklist.db_path`).

Fields:

- `enabled` (bool, default true).
- `default_ttl` (duration, default `24h`) — TTL for new entries when not otherwise specified.
- `max_entries_per_tenant` (int, default 100000) — hard cap; on overflow the oldest entries are evicted.
- `promote_from_rate_limit` (bool, default false) — when true, repeated rate-limit triggers add the client to this list for `default_ttl`.
- `promote_after_triggers` (int, default 10) — number of rate-limit triggers before promotion, only used if the above is true.
- `action` (string, default `drop`) — `drop`, `404`, `429`, `timeout`.

Global default in P1: enabled, 24h TTL, promotion off.

Tenant override example:

```yaml
features:
  ttl_blocklist:
    enabled: true
    default_ttl: 72h
    promote_from_rate_limit: true
    promote_after_triggers: 6
```

The BoltDB file contains one bucket per tenant. Stale entries are evicted lazily on read; there is no background sweep in P1 other than the per-tenant cap.

## content_sanitizer

Streams HTML responses through a token filter that strips configured tags. Applied only when `Content-Type: text/html` (with or without charset). Non-HTML responses pass through untouched.

Fields:

- `enabled` (bool, default false).
- `strip_tags` ([]string, default `[script, object, embed, iframe]`) — tag names (lowercase) to remove. The tag and its children are dropped.
- `strip_attrs` ([]string, default `[onclick, onload, onerror, onmouseover]`) — attributes to remove from any remaining tag.
- `max_body_mb` (int, default 16) — safety cap. Responses exceeding this are passed through unmodified (sanitization is best-effort, not a guarantee on unbounded streams).

Global default in P1: disabled. Enable per tenant that needs it.

Tenant override example:

```yaml
features:
  content_sanitizer:
    enabled: true
    strip_tags: [script, object, embed, iframe, form]
    strip_attrs: [onclick, onload, onerror, onmouseover, onfocus, onblur]
    max_body_mb: 32
```

Limits: 64 tags and 128 attributes per tenant. Note that content sanitizing is a best-effort defense; it does not parse CSS `expression()`, does not handle JavaScript-encoded HTML embedded in attributes, and does not rewrite URLs.

## negative_cache

Tracks backend failures and temporarily excludes failing backends from selection. This is not HTTP caching; it is a circuit-breaker over the backend selection step.

Fields:

- `enabled` (bool, default true).
- `ttl` (duration, default `5m`) — how long a backend stays cold after it is marked.
- `failure_threshold` (int, default 5) — number of consecutive failures that trigger marking.
- `failure_kinds` ([]string, default `[connect, timeout, 5xx]`) — what counts as a failure.

Global default in P1: enabled, 5m TTL, 5 failures.

Tenant override example:

```yaml
features:
  negative_cache:
    enabled: true
    ttl: 10m
    failure_threshold: 3
```

The negative cache is in-process per edge; it is not shared across edges. Each edge learns independently which backends are cold.

## proxy_headers

Adds or strips request and response headers. Supports simple templates in values: `{{client_ip}}`, `{{tenant_host}}`, `{{request_id}}`.

Fields:

- `strip_upstream` ([]string) — headers to remove from the request before it goes to the backend.
- `add_upstream` ([]{name,value}) — headers to add (or overwrite) on the request.
- `strip_downstream` ([]string) — headers to remove from the response before returning to the client.
- `add_downstream` ([]{name,value}) — headers to add on the response.

There is no global `enabled` flag; this feature is configured by lists. Empty lists are the effective default.

Global default in P1:

```yaml
features:
  proxy_headers:
    strip_upstream: [Server, X-Powered-By, Via]
    add_downstream:
      - { name: X-Frame-Options,        value: DENY }
      - { name: X-Content-Type-Options, value: nosniff }
```

Tenant override example:

```yaml
features:
  proxy_headers:
    strip_upstream: [Server, X-Powered-By, Via, X-AspNet-Version]
    add_upstream:
      - { name: X-Forwarded-For,   value: "{{client_ip}}" }
      - { name: X-Forwarded-Proto, value: https }
      - { name: X-Forwarded-Host,  value: "{{tenant_host}}" }
    add_downstream:
      - { name: Strict-Transport-Security, value: "max-age=63072000; includeSubDomains" }
      - { name: Referrer-Policy,           value: no-referrer }
      - { name: Content-Security-Policy,   value: "default-src 'self'" }
```

Limits: 64 headers in each list, 256 bytes per name or value.

## abuse_api

Exposes a JSON endpoint where third parties can report abuse of a specific onion backend. Received reports are stored in BoltDB and optionally emailed.

Fields:

- `enabled` (bool, default true).
- `path` (string, default `/_abuse`) — the HTTP path relative to the tenant host. Must start with a slash.
- `notify_email` (string, default null) — when set, the hub sends an email per report to this address. Null means store only.
- `rate_limit_rpm` (int, default 10) — maximum reports accepted per minute per client IP.

Global default in P1: enabled on `/_abuse`, no email.

The POST body is JSON:

```json
{
  "onion": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion",
  "reason": "phishing",
  "contact": "reporter@example"
}
```

Tenant override example:

```yaml
features:
  abuse_api:
    enabled: true
    path: /_abuse
    notify_email: abuse@your-domain.example
    rate_limit_rpm: 5
```

Abuse reports are exposed via the hub admin API under `GET /v1/abuse`. They are never exposed on the public edge surface.

## static_cache

In-process response cache for static assets, backed by Ristretto. Keyed on `tenant.host + request.path`.

Fields:

- `enabled` (bool, default true).
- `extensions` ([]string, default `[.js, .css, .png, .jpg, .svg, .woff2]`) — file extensions considered cacheable.
- `max_object_mb` (int, default 5) — per-object size cap. Larger responses bypass the cache.
- `default_ttl` (duration, default `5m`) — TTL for cached entries.
- `honor_cache_control` (bool, default true) — when true, `Cache-Control: no-store` on the upstream response bypasses the cache.

The bootstrap config sets `features.static_cache.max_size_mb` as the global cache size across all tenants. This is not per-tenant because all tenants share the same cache instance, but per-key accounting uses `tenant.host` so one tenant cannot starve another of hit rate in practice (Ristretto uses cost-based admission).

Global default in P1: enabled, common extensions, 5 MB per object, 5 minute TTL.

Tenant override example:

```yaml
features:
  static_cache:
    enabled: true
    extensions: [.js, .css, .png, .jpg, .svg, .woff2, .ttf, .eot]
    max_object_mb: 8
    default_ttl: 1h
```

Concurrent cache misses for the same key serialize through an inflight map; only one upstream fetch happens per (tenant, path), preventing thundering-herd on cold cache.

## stealth_hs

Stealth hidden-service client authorization. Configured per tenant because the `x25519` private keys are per destination. Not a request-path middleware: it is a hub-startup concern.

Fields:

- `enabled` (bool, default false).
- `client_auths` ([]{onion, auth_private_key_file}).

When the hub starts (or reloads), it scans every tenant's `stealth_hs.client_auths` and writes the auth files into the `ClientOnionAuthDir` of every running Tor instance. Tor picks the correct key at dial time based on destination address.

Tenant override example:

```yaml
stealth_hs:
  enabled: true
  client_auths:
    - onion: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
      auth_private_key_file: /var/lib/gateway/hub/stealth/tenant-a.auth_private
    - onion: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion"
      auth_private_key_file: /var/lib/gateway/hub/stealth/tenant-b.auth_private
```

Runtime add and remove of stealth keys is not supported in P1. Adding or removing an entry requires a hub restart for Tor instances to pick up the change. Improved hot-reload for this is a future concern (planned for P2 alongside check-host.net integration, so the door can rotate auth for rotated mirrors).

Limits: 32 auth entries per tenant. Auth files must be readable by the `gateway` user and must be within `/var/lib/gateway/hub/`.

## onion_validator

Not a runtime middleware; runs at tenant load time. Rejects any backend that is not a valid v3 `.onion` address.

Fields: none. The validator is always on.

Behavior: reads each backend `addr`, checks that it lowercases to itself, matches `^[a-z2-7]{56}\.onion$`, and has the correct checksum byte per the v3 descriptor (Tor Rend-Spec v3 §6). Failure rejects the tenant with an error naming the specific backend.

## Interaction order

Middlewares execute in this fixed order per request (after TLS and tenant lookup):

1. admin gate (if enabled) — matched path returns 501 without invoking anything else.
2. metrics — increments request counter.
3. cloudflare — drops requests from non-Cloudflare IPs when CF mode is strict.
4. proxy_headers (request-side) — strip and add request headers.
5. blocklist_regex — match path and headers.
6. geoip — block-country check.
7. rate_limit — token bucket per IP.
8. ttl_blocklist — live-entry check.
9. static_cache — serve cached, if hit.
10. upstream dial — negative_cache filters the backend set.
11. content_sanitizer — streaming filter on `text/html` responses.
12. proxy_headers (response-side) — strip and add response headers.

Any middleware that returns a terminal response (block, 404, 429, cached hit) stops the chain. The response-side proxy_headers still run on the short-circuit response.

## Metrics

Every feature publishes its own counters. Tenant labels are hashed by default (see `opsec.md`):

- `gateway_blocklist_regex_matches_total{tenant, action}`
- `gateway_geoip_blocks_total{tenant, country}`
- `gateway_rate_limit_exhaustions_total{tenant, bucket}`
- `gateway_ttl_blocklist_entries{tenant}`
- `gateway_content_sanitizer_strips_total{tenant, tag}`
- `gateway_negative_cache_cold_backends{tenant}`
- `gateway_static_cache_hits_total{tenant}`
- `gateway_static_cache_misses_total{tenant}`
- `gateway_abuse_reports_received_total{tenant}`

The country label on `gateway_geoip_blocks_total` is not hashed because the ISO codes are not identifying in the same way hostnames are; operators may need the country label to tune block lists.
