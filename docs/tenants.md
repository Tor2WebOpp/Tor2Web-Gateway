# Tenants

A tenant is a public `Host` served by the gateway mapped to one or more `.onion` backends, with its own middleware configuration. This document describes the YAML file layout, the fields, how to add and remove tenants via either file-based management or the hub admin API, and the lifecycle of a tenant from creation to deletion.

For the bootstrap config schema (mode, transport, admin gate, etc.) see `config.example.yaml` at the repo root and the introduction in `architecture.md`. For per-feature parameters and per-tenant overrides see `features.md`.

## Where tenants live

In remote mode, tenants live on the hub only. Each tenant is one YAML file under:

```
/var/lib/gateway/hub/runtime/tenants/<host>.yaml
```

The filename base must match the `host:` field inside the file. The hub watches this directory with `fsnotify` and reloads on any change. Edges do not read this directory; they receive the tenant set from the hub via the config stream.

In local mode, the same layout is used, but the directory is typically `/etc/gateway/runtime/tenants/`. The local `gateway-proxy` watches it directly; there is no hub and no config stream.

Alongside the tenants directory, one file holds the global defaults:

```
/var/lib/gateway/hub/runtime/globals.yaml
```

Globals define the default feature toggles and block-response mode. Any tenant that does not override a feature inherits from globals.

## Minimal tenant

The smallest valid tenant file:

```yaml
host: example.your-domain.example
enabled: true
backends:
  - addr: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
    weight: 1
```

Drop this into the runtime tenants directory. The hub will reload within the `fsnotify` debounce window (50 ms) and begin serving that host. Edges pick it up from the next config-stream delta.

## Full tenant schema

```yaml
# Required. Lowercased public host. Must match the filename base.
host: example.your-domain.example

# Required. Set to false to soft-disable the tenant. A disabled tenant
# triggers the configured block_response for all matching requests.
enabled: true

# Required. At least one backend. Each backend must be a valid v3 onion
# address (56 base32 characters + .onion). v2 is rejected at load time.
backends:
  - addr: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
    weight: 1
  - addr: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion"
    weight: 2

# Optional. Which nodes serve this tenant. Default "*" means all proxy
# nodes registered with the hub. Named list restricts traffic to the
# listed edges only. Use this for canary rollouts or regional isolation.
assigned_nodes: "*"

# Optional. Response behavior when the tenant is disabled, GeoIP-blocked,
# rate-limited, regex-blocked, or ttl-blocked. Inherits from globals if
# omitted.
block_response:
  default: drop             # drop | timeout | 404 | 429
  timeout_seconds: 30       # only used when default == timeout

# Optional. Feature overrides. Omitted features inherit from globals.
# Enabled=true with no params means "use global params with feature on".
features:
  blocklist_regex:
    enabled: true
    patterns:
      - pattern: "(?i)wp-(login|admin)"
        action: 404
      - pattern: "\\.env$"
        action: drop
      - pattern: "^/(xmlrpc|debug|test)"
        action: 429
  geoip:
    enabled: true
    block_countries: [CN, IR, RU]
    action: 404
  rate_limit:
    enabled: true
    per_ip_rps: 3
    per_ip_burst: 6
  content_sanitizer:
    enabled: true
    strip_tags: [script, object, embed, iframe]
  ttl_blocklist:
    enabled: true
    default_ttl: 24h
  static_cache:
    enabled: true
    extensions: [.js, .css, .png, .jpg, .svg, .woff2]
  proxy_headers:
    strip_upstream:
      - Server
      - X-Powered-By
      - X-AspNet-Version
      - Via
    add_upstream:
      - { name: X-Forwarded-For,   value: "{{client_ip}}" }
      - { name: X-Forwarded-Proto, value: https }
      - { name: X-Forwarded-Host,  value: "{{tenant_host}}" }
    strip_downstream:
      - X-Debug
    add_downstream:
      - { name: X-Frame-Options,       value: DENY }
      - { name: X-Content-Type-Options, value: nosniff }
      - { name: Referrer-Policy,        value: no-referrer }

# Optional. Negative cache for failing backends.
negative_cache:
  enabled: true
  ttl: 5m
  failure_threshold: 5

# Optional. Stealth hidden-service client authorization. Enabled per
# tenant because the x25519 private keys are per destination, not global.
# Files must exist on the hub and be readable by the gateway user.
stealth_hs:
  enabled: false
  client_auths:
    - onion: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion"
      auth_private_key_file: /var/lib/gateway/hub/stealth/example-bbb.auth_private

# Optional. Abuse report endpoint for this tenant.
abuse_api:
  enabled: true
  path: /_abuse
  notify_email: null   # null = store only; otherwise email on each report
```

Any field not listed here is rejected by the validator. The reload aborts and keeps the previous registry live; the hub logs the specific tenant and field that failed.

## Onion address validation

A backend address must be exactly 56 characters of RFC 4648 base32 (lowercase a-z and digits 2-7) followed by `.onion`. The validator rejects:

- Addresses that are not 56+6 characters total.
- v2 addresses (16-character base32).
- Any character outside the base32 alphabet.
- Mixed case (addresses are lowercased before validation; if the lowercased form does not equal the original, the tenant fails to load so operators notice accidental capitalization).

This check runs both at tenant load and on every admin-API PUT. The error message names the specific backend and the specific reason.

## Managing tenants via config files

The file-based workflow is the default. Edit files under `runtime/tenants/`; `fsnotify` picks up changes. A few operational rules:

Move files in atomically. The pattern the hub expects is:

```bash
sudo install -o gateway -g gateway -m 0640 \
  /tmp/newtenant.yaml \
  /var/lib/gateway/hub/runtime/tenants/newtenant.your-domain.example.yaml
```

Using `install` (or `mv` from the same filesystem) guarantees the hub sees either the old file or the new file, not a half-written one. Editing in place with an editor that writes through a tempfile-and-rename (vim with `:set backupcopy=no`, for example) is also safe.

Delete a tenant by removing its file. The hub marks the tenant `deleted: true` for a grace period (60 seconds by default), during which in-flight requests finish; after the grace period the tenant is evicted from the registry and edges see the delta.

Rename a tenant (change its host) by adding the new file and then removing the old one after the new file is confirmed loaded. Do not rename the file directly; the validator will reject a file whose `host:` field does not match the filename base.

## Managing tenants via the admin API

For automated provisioning, use the hub admin API. All calls require mTLS with an edge or admin client certificate signed by the hub CA.

Create or update:

```bash
curl -sS --cert /etc/gateway/admin.crt --key /etc/gateway/admin.key \
     --cacert /etc/gateway/hub-ca.crt \
     -X PUT https://10.0.0.1:9080/v1/tenants/example.your-domain.example \
     -H 'Content-Type: application/yaml' \
     --data-binary @example.yaml
```

The hub writes the file to `runtime/tenants/example.your-domain.example.yaml` atomically and returns 200 with the parsed tenant JSON on success.

List tenants:

```bash
curl -sS --cert /etc/gateway/admin.crt --key /etc/gateway/admin.key \
     --cacert /etc/gateway/hub-ca.crt \
     https://10.0.0.1:9080/v1/tenants
```

Delete:

```bash
curl -sS --cert /etc/gateway/admin.crt --key /etc/gateway/admin.key \
     --cacert /etc/gateway/hub-ca.crt \
     -X DELETE https://10.0.0.1:9080/v1/tenants/example.your-domain.example
```

Full request/response schemas are in `hub-api.md`.

## Globals

`globals.yaml` defines the feature defaults and the default block response. It is loaded at hub start and hot-reloaded on file change.

```yaml
block_response:
  default: drop
  timeout_seconds: 30

features:
  blocklist_regex:
    enabled: true
    default_action: drop

  geoip:
    enabled: false
    db_path: /var/lib/gateway/geoip/GeoLite2-Country.mmdb
    default_action: 404

  rate_limit:
    enabled: true
    per_ip_rps: 10
    per_ip_burst: 20

  ttl_blocklist:
    enabled: true
    default_ttl: 24h

  content_sanitizer:
    enabled: false
    strip_tags: [script, object, embed, iframe]

  negative_cache:
    enabled: true
    ttl: 5m
    failure_threshold: 5

  static_cache:
    enabled: true
    extensions: [.js, .css, .png, .jpg, .svg, .woff2]
    max_size_mb: 256

  proxy_headers:
    strip_upstream: [Server, X-Powered-By, Via]
    add_downstream:
      - { name: X-Frame-Options,        value: DENY }
      - { name: X-Content-Type-Options, value: nosniff }

  abuse_api:
    enabled: true
    path: /_abuse
```

A tenant inherits every global setting it does not override. Setting a feature to `enabled: false` on a tenant turns the feature off for that tenant even if it is on globally. Setting a feature to `enabled: true` with no params uses the global params.

## Tenant lifecycle

Creation: file appears under `runtime/tenants/` (via filesystem or admin-API PUT). The hub validates the file against the schema and the feature registry. On success it adds the tenant to the registry and pushes a delta to every connected edge on the config stream. On failure the error is logged (and returned over the admin API). The file is not removed; the operator must fix or delete it.

Update: the same flow. The hub compares the new parsed struct to the current one; unchanged fields are not touched; changed fields are swapped atomically. In-flight requests hold a reference to the old tenant via context and finish on the old config.

Disable: set `enabled: false`. The tenant stays in the registry, but every request to its host triggers the configured block response. Use this for temporary take-downs without losing the config.

Soft delete: remove the file (or admin-API DELETE). The hub sets a `deleted_at` timestamp internally and keeps the tenant routable for `deletion_grace` seconds (60 by default). During this window, new requests still match but return 410 Gone. After the grace window, the tenant is removed from the registry and edges see the delta.

Restore: re-add the file before the grace window expires. The tenant is restored with its previous config; any in-flight 410s continue returning 410, subsequent requests succeed.

## Examples

A conservative public tenant with strict headers and rate limiting:

```yaml
host: shop.your-domain.example
enabled: true
backends:
  - addr: "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.onion"
    weight: 1
features:
  rate_limit:
    enabled: true
    per_ip_rps: 5
    per_ip_burst: 10
  blocklist_regex:
    enabled: true
    patterns:
      - pattern: "(?i)(wp-|xmlrpc|phpmyadmin)"
        action: 404
      - pattern: "\\.(env|git|htaccess)$"
        action: drop
  geoip:
    enabled: true
    block_countries: [CN, IR]
    action: 404
  proxy_headers:
    add_downstream:
      - { name: Strict-Transport-Security, value: "max-age=63072000; includeSubDomains" }
      - { name: X-Frame-Options,           value: DENY }
      - { name: Content-Security-Policy,   value: "default-src 'self'" }
  content_sanitizer:
    enabled: true
```

A tenant that only runs on two named edges:

```yaml
host: canary.your-domain.example
enabled: true
assigned_nodes:
  - edge-7a3c
  - edge-1d2e
backends:
  - addr: "ddddddddddddddddddddddddddddddddddddddddddddddddddddddddd.onion"
    weight: 1
```

A tenant with stealth client authorization on a single backend:

```yaml
host: private.your-domain.example
enabled: true
backends:
  - addr: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.onion"
    weight: 1
stealth_hs:
  enabled: true
  client_auths:
    - onion: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.onion"
      auth_private_key_file: /var/lib/gateway/hub/stealth/private-eee.auth_private
```

A tenant with all middleware intentionally off (for diagnostic passthrough only):

```yaml
host: debug.your-domain.example
enabled: true
backends:
  - addr: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff.onion"
    weight: 1
features:
  blocklist_regex: { enabled: false }
  geoip:           { enabled: false }
  rate_limit:      { enabled: false }
  ttl_blocklist:   { enabled: false }
  content_sanitizer: { enabled: false }
  static_cache:    { enabled: false }
  abuse_api:       { enabled: false }
```

Do not leave a debug tenant live for longer than needed; it bypasses every protection.

## Limits

The validator rejects tenants that exceed these limits:

- More than 32 backends.
- More than 256 regex patterns in `blocklist_regex`.
- Regex patterns longer than 512 characters.
- Rate-limit RPS values over 10000.
- Block-countries list with more than 256 entries.
- Custom headers with names or values over 256 bytes.

These limits are conservative; the goal is to reject clearly malformed or DoS-shaped configuration at load time rather than at request time.
