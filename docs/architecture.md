# Architecture

This document describes how the gateway is built internally: the four binaries, the two deployment modes, the configuration pipeline, the request path through the middleware chain, and the interfaces between components. For the operational how-to see `deployment.md`; for tenant and feature configuration see `tenants.md` and `features.md`; for the door redirector and mirror-health integration see `door.md`, `mirrors.md`, and `checkhost.md`.

## Binaries

There are four binaries. Which ones run depends on the mode.

`gateway-proxy` is the public-facing reverse proxy. It terminates TLS on port 443, runs the middleware chain, maps `Host` headers to tenants, and forwards upstream requests over SOCKS5 through a Tor instance. In local mode it dials the torpool over a Unix socket on the same machine; in remote mode it dials the hub's SOCKS port over whichever transport is configured. Edge proxies are meant to be disposable.

`gateway-torpool` manages the Tor process pool. It spawns instances between `min_instances` and `max_instances`, allocates SOCKS ports starting from `socks_base_port`, probes each instance every 30 seconds, and replaces dead instances in place on their existing SOCKS port so that the proxy side never has to relearn port numbers. It exposes a small JSON API on a Unix socket: `GET /backends` for the current list of live SOCKS ports with their observed latency and error counts, `GET /health` for overall pool state, `POST /scale` to force min/max, `GET /stats` for diagnostic detail.

`gateway-hub` is introduced in P1. It wraps `gateway-torpool` internally and adds four things on top of it: the tenant registry, the admin and config API, the mTLS certificate authority that signs edge client certs, and (new in P2) the mirror-health registry driven by the check-host.net client. In remote mode `gateway-torpool` is not deployed as a separate process; its code is linked into the hub and reached through the same Unix socket, which is only visible inside the hub process tree.

`gateway-door` is new in P2. It is a small, stateless redirector with no `.onion` reach of its own. It serves a static cover page on `/`, matches constant-time against a list of opaque slug strings on other paths, and emits an HTTP 302 to one of the currently-healthy mirror hostnames. Doors connect to the hub over the same transport as edges and read their runtime config (cover kind, slug list, mirror snapshot) from the existing config stream. See `door.md` for the full description.

## Deployment modes

Local mode puts `gateway-proxy` and `gateway-torpool` on one machine. They talk over `/run/gateway/torpool.sock`. There is no hub, no mTLS, no WireGuard. The tenant registry is still used, but it reads from a local directory rather than from a hub, and it does not stream updates. This mode preserves the pre-P1 single-box deployment and adds multi-tenancy, feature toggles, and the phased installer to it.

Remote mode separates the edge from the center. One hub runs `gateway-hub` and `gateway-torpool` (the latter embedded). N edges run `gateway-proxy`, each with its own public TLS certificate and its own `node_id`. Edges never reach clearnet out to tenant backends: all upstream traffic goes through the hub's Tor pool. The machines that sit in front of the public internet are therefore a separate set from the machines that see the `.onion` dial targets.

There is no federation in P1. A hub does not talk to other hubs. If you need geographic spread, run multiple independent hubs with independent tenant lists.

## Transport interface

The transport is an abstraction inside `internal/transport/`:

```go
type Transport interface {
    DialSOCKS(ctx context.Context, port int) (net.Conn, error)
    AdminClient() *http.Client
    Close() error
}
```

`DialSOCKS` returns a connection that behaves like a direct TCP dial to the hub's SOCKS5 port. `AdminClient` returns an `http.Client` that reaches the hub admin API. `Close` tears down long-lived resources such as the WebSocket pool in `https_tunnel` mode.

Three implementations, one for each transport kind:

`wireguard` is the simplest. A WireGuard tunnel is brought up at install time. The hub's admin API and SOCKS5 listener bind to `10.0.0.1` only. `DialSOCKS` becomes a plain TCP dial to `10.0.0.1:<port>`; `AdminClient` returns `http.DefaultClient` pointed at `http://10.0.0.1:9080`. No custom framing, no per-connection setup cost, reuses the existing SOCKS5 client code verbatim.

`https_tunnel` is used when UDP is unavailable. The hub exposes an HTTPS listener with mTLS; edges open a WebSocket and send a small JSON framing protocol: `{"op":"dial","port":N}` opens a stream, after which raw bytes are forwarded. Admin API calls are plain HTTPS on the same endpoint, authenticated by the same client certificate. Userspace framing means higher CPU and higher latency than wireguard.

`socks5_tls` exposes two public TLS ports on the hub: `:9443` for SOCKS5-inside-TLS and `:9444` for the admin HTTPS. Both require mTLS client certs. This is the fingerprintable option; it is the last resort and the installer prints a warning when it is selected.

Transport is not a runtime choice. It is bootstrap config. Switching transports requires reconfiguring both sides and restarting.

## Configuration pipeline

The gateway uses three layers of configuration with strict separation.

Layer 1 is bootstrap. It is `config.yaml` on each machine. It is written once by the installer, read once on process start, and never changes at runtime. It carries things that cannot be safely hot-reloaded: mode, node type, transport kind, TLS listener addresses, mTLS file paths, hub address, admin slug and tokens. Changing this file requires a restart.

Layer 2 is runtime. It lives only on the hub, under `$HUB_DATA_DIR/runtime/`. It is two things: `globals.yaml` with global feature defaults, and one file per tenant under `tenants/<host>.yaml`. The hub watches the directory with `fsnotify`; on change, it validates the whole set across every tenant and every feature and only if validation succeeds does it swap the in-memory registry. Edges receive the initial snapshot over the admin API and then subscribe to a long-poll stream at `GET /v1/config/stream?node_id=X` which delivers deltas.

Layer 3 is secrets. These never appear in bootstrap or runtime YAML. They live in separate files with mode 0600 or as env vars for docker-compose: `node-secret`, `wg-private.key`, `client.crt` and `client.key`, `metrics-salt`, `hub-ca.key`. The installer generates them, writes them to `/etc/gateway/` with the correct mode, and prints the one-time admin URL to stdout. No secret is ever written to a log file.

## Request path through an edge

1. TLS terminates on port 443. CertMagic manages the certificate via ACME HTTP-01 on port 80.
2. The inner HTTP server dispatches to `proxy.Server.ServeHTTP`.
3. If the admin gate is enabled and `r.URL.Path` matches `/<slug>/<token1>/<token2>/` under constant-time comparison, the request is handed to the admin handler. In P1 this returns 501. Matching paths are not logged.
4. Otherwise the server extracts `r.Host`, strips the port, lowercases it, and looks it up in the tenant registry. A miss returns HTTP 421 Misdirected Request.
5. If the tenant exists but `tenant.enabled == false`, the configured `block_response` is applied (`drop`, `timeout`, `404`, or `429`).
6. The tenant is stashed in the request context. Every middleware below reads it from context and applies tenant-specific overrides.
7. Metrics middleware increments `gateway_requests_total` with the hashed tenant label.
8. Cloudflare middleware (if enabled) verifies the client IP against the current Cloudflare range set.
9. Security-headers middleware attaches HSTS, X-Frame-Options, X-Content-Type-Options, and anything configured under `tenant.features.proxy_headers.add_downstream`.
10. `blocklist_regex` compiled patterns are matched against path and headers. Match triggers the configured action: `drop`, `404`, `429`, or `timeout`.
11. `geoip` looks up the client IP in the MaxMind database. Countries listed in `tenant.features.geoip.block_countries` trigger the action, typically `404`.
12. `rate_limit` pulls the per-IP bucket keyed on `tenant.host + client_ip`. Exhaustion triggers the block response.
13. `ttl_blocklist` checks whether this IP has a live entry. Rate-limit exhaustion or repeated regex matches can write entries here with TTL.
14. `static_cache` serves cached responses for static extensions. Cache key includes `tenant.host + path`.
15. The reverse proxy handler picks a tenant backend according to weight and negative-cache state, dials the hub via `transport.DialSOCKS(port)` with the SOCKS port from the backend list (the edge picks which instance; backend list comes from the hub's torpool), and forwards the request through SOCKS5.
16. Upstream response goes back through `content_sanitizer` (streams HTML through a token filter that strips configured tags, only for `Content-Type: text/html`) and `proxy_headers` response rules before hitting the client.

The `negative_cache` feature is checked before step 15 and updated by the response handler. If a backend fails N times in a row it goes cold for the configured TTL and is excluded from selection.

## Tenant registry

The registry is an in-memory `map[string]*Tenant` guarded by an `sync.RWMutex`. It is populated from `$HUB_DATA_DIR/runtime/tenants/*.yaml` on hub start. The hub watches the directory with `fsnotify` and reloads on any file event. A reload is atomic: it reads every file, validates every tenant, and only after full success does it swap the map pointer under the write lock. Requests in flight hold a reference to the previous map via context, so they finish on the old config without races.

Edges get their copy of the registry from the hub. The registration flow is: the edge POSTs `/v1/nodes/register` with its `node_id` and a freshly generated CSR, the hub signs the CSR under its mTLS CA, and the edge opens `GET /v1/config/stream?node_id=X` authenticated with the new client cert. The stream is long-poll: initial payload is a full snapshot, subsequent payloads are JSON-encoded deltas. On disconnect the edge reconnects with exponential backoff capped at 30 seconds.

Tenant isolation is enforced in the middleware layer, not at the Tor level. All tenants share the same pool. Stealth client authorization is the only per-destination Tor setting and is handled by dropping `x25519` private keys into every Tor instance's `ClientOnionAuthDir`; Tor picks the correct key by destination address without the proxy needing to route based on tenant.

## Feature registry

Features are middleware modules under `internal/feature/<name>/`. Each exports two things: a `Configure(cfg FeatureConfig)` method for idempotent reconfiguration, and a `Middleware(next http.Handler) http.Handler` that returns a `next`-passthrough handler when disabled. The passthrough branch is a direct function return and allocates nothing, so feature toggles are effectively free at request time when the feature is off.

Per-request configuration resolution walks three layers:

1. Tenant-specific override, if `tenant.features[name]` is set.
2. Global default from `globals.features[name]`.
3. Hardcoded safe default (disabled, zero values).

Validation runs on every reload for every tenant and every feature. Any `Validate()` error aborts the swap and keeps the previous registry live. This means configuration that would fail at runtime is rejected at reload time before it can affect traffic.

## Torpool and backend selection

The torpool manager spawns Tor instances with deterministic port allocation. Instance 0 gets `socks_base_port`, instance 1 gets `socks_base_port + 1`, and so on. When an instance dies, it is respawned on the same port; the backend list the hub returns to edges therefore does not churn as instances are replaced. Health probes run every 30 seconds against the Tor control port. An instance is considered dead if the control-port probe fails twice in a row or the SOCKS connection refuses for more than five seconds.

The scaler maintains pool size between `min_instances` and `max_instances`. Scale up fires when the fraction of busy instances crosses `scale_up_threshold` for one probe interval. Scale down fires when it drops below `scale_down_threshold` and stays there for at least `scale_cooldown`. The scaler never removes the last healthy instance even if the thresholds would suggest it.

Edge backend selection uses a score per instance: `score = (active_conns * 2) + (latency_ms / 100) + (error_rate * 10)`. Lower is better. The edge picks the lowest-scored live instance that is not currently cold in the negative cache. If the selected instance's SOCKS dial returns a retryable error (502, 503, 504, timeouts on connect), the proxy retries on the next-best instance up to `pool.retry_attempts` times before returning the client an error.

Each SOCKS port has a circuit breaker that opens at 50% observed failure rate over a sample of 10 or more recent requests. An open breaker takes the instance out of the selection set for one probe interval before half-opening it for a single trial request.

## mTLS CA and edge registration

The hub holds a self-signed root CA in `hub.mtls_ca.cert_file` and `hub.mtls_ca.key_file`. It signs an intermediate once at install time and issues edge client certificates from the intermediate. The CA private key lives on the hub only; edges never see it. They see the root for TLS verification in the `https_tunnel` and `socks5_tls` transports.

Edge registration: `POST /v1/nodes/register` with `{node_id, public_key, node_type, csr}`. The node-secret in the POST body proves initial trust. The hub validates, signs the CSR, and returns the signed cert. The edge stores it at `mtls.client_cert_file`. From that point on, every edge-to-hub call is authenticated with the cert.

Revocation is a CRL file on the hub, reloaded every 60 seconds. An edge whose cert is revoked will see its config stream close and will stop accepting new connections after `grace_seconds` (default 30). The edge does not reconnect once the cert is revoked; an operator must manually reprovision it.

Certificate lifetime is one year by default. Automatic rotation is a P3 concern. P1 operators rotate manually by rerunning the installer's registration step.

## OPSEC touchpoints in the code

Several OPSEC constraints are enforced at specific spots in the code and are worth naming so nobody accidentally regresses them.

Metrics labels for tenants go through `sha256(host + salt)[:16]` before they are attached to any counter or histogram. The salt is `/etc/gateway/metrics-salt`, generated once by the installer. If the salt file is missing, metrics collection refuses to start rather than falling back to plaintext labels.

Logs route through a single `anonymize_ip` helper that zeros the last IPv4 octet and the last IPv6 /64. Any log line that constructs its own IP string instead of using this helper is a bug.

The admin gate match is always constant-time across all three segments. Short-circuiting on the first mismatch is rejected by review. The logging filter is wired at the `http.Handler` layer above the standard access logger, so even if a future operator changes the access logger, admin paths still do not appear.

Edges make no outbound calls except to the hub (via transport) and to tenant backends (via SOCKS5 through the hub). There is no update check, no telemetry, no analytics. Any new outbound must be explicitly added to a whitelist in `internal/proxy/egress.go` and reviewed.

## Door role and mirror-health

The door is the fourth node type and sits alongside edges and hubs. Architecturally it is a cut-down edge: same transport, same mTLS, same config-stream subscription, but no middleware chain and no upstream dial. A door's entire serving surface is a cover handler on `/` and a slug matcher on other paths. On a slug hit, the door queries its local cache of the mirror-health registry (pushed from the hub over the config stream), filters by the slug's strategy and exclude-regions, and emits a 302 at a chosen mirror hostname.

The mirror-health registry is owned by the hub and lives under `$HUB_DATA_DIR/runtime/mirrors/<host>.yaml`. A background worker on the hub polls check-host.net every `interval` (default 15 minutes) for each registered mirror across the operator-chosen region list. The worker writes per-region results into the mirror record, recomputes the verdict (`live`, `degraded`, `blocked`, `unknown`) on every update, and pushes the registry delta to every subscribed door through the existing config stream.

Doors do not call check-host.net. They do not see tenant backend lists. They do not hold TLS certificates for any tenant. Their compromise reveals the slug list and the set of public mirror hostnames, both of which are already externally observable, and nothing else.

Updated deployment diagram:

```
 Client ──HTTPS──▶  door-1   │ cover + 302
                   door-2    │
                             └──(config only)──┐
                                               │
                   edge-1                      │
 Client ──HTTPS──▶ edge-2   ──▶  gateway-hub  ──SOCKS5──▶ Tor × N ──▶ .onion
                   edge-N        • torpool
                                 • tenants
                                 • mirrors + check-host
                                 • admin API
                                 • mTLS CA
                                (private network:
                                 wg / https / socks-tls)
```

The door leg carries only control traffic to the hub (config stream, heartbeat). User traffic on the door side is answered locally — either the cover asset or a 302 that sends the client directly at a public mirror hostname. The door is not on the request path for tenant content, which is what makes it cheap and disposable.

## What P1 does not build

P1 does not build the `gateway-door` binary, which is delivered in P2 as described above. P1 does not build check-host.net polling (delivered in P2) or the mirror auto-rotation that depends on it. P1 does not implement the admin-gate handler body (P3); only the routing carve-out and the constant-time matcher. P1 does not build the admin UI (P4) or the i18n translation catalogs beyond stubs (P5). Federation between hubs is not planned.
