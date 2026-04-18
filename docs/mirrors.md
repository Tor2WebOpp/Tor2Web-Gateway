# Mirrors

A mirror in this model is a public hostname that fronts one or more tenant backends. Every edge proxy is a mirror; a tenant with three edges serving it has three mirrors. The mirror-health registry is the hub's view of which of those public hostnames are currently reachable, which are slow, and which are blocked in specific regions. Doors consume this view when picking a redirect target. Operators consume it when rotating stale edges out of service.

The registry is stored under `$HUB_DATA_DIR/runtime/mirrors/<host>.yaml`, one file per mirror, using the same atomic-reload pattern as the tenant registry. `fsnotify` watches the directory; changes validate across the whole set and only swap the in-memory registry on full success. Mirrors are not tenants: a mirror record describes the public face, not the backends behind it. The tenant registry says what `.onion` the mirror's backend traffic resolves to; the mirror registry says whether the public hostname itself is answering from a given measurement region.

## Record shape

```yaml
host: mirror-3.your-domain.example
tenants: ["example.your-domain.example"]
weight: 1
manual_block: false
manual_note: ""
verdict: live
last_check: "2026-04-18T10:00:00Z"
blocked_count: 0
total_checked: 12
regions:
  us1:
    status: ok
    latency: 180
    at: "2026-04-18T10:00:00Z"
  de1:
    status: ok
    latency: 220
    at: "2026-04-18T10:00:00Z"
```

Fields:

- `host` — public hostname served by this mirror. Must be unique across the registry.
- `tenants` — which tenants this mirror is permitted to serve. Empty list means all tenants (common for fleet-wide edges); a named list restricts which tenants the door will consider when this mirror is a candidate.
- `weight` — selection weight used by the `weighted` strategy on doors. Default 1. Weight 0 disables without removing.
- `manual_block` — operator-set hard block. When true, the verdict is forced to `blocked` regardless of health data.
- `manual_note` — free-form note that accompanies a manual block, visible in admin API output and in hub logs. Used for handovers ("blocked 2026-04-15, provider complaint ticket 12345").
- `verdict` — computed field; one of `live`, `degraded`, `blocked`, `unknown`. Not operator-set.
- `last_check` — RFC 3339 timestamp of the last completed health pass for this mirror.
- `blocked_count` / `total_checked` — counters since the mirror was registered. Used for operational visibility; not used in the verdict calculation (which only considers the current regions map).
- `regions` — map keyed on region id (either ISO-3166 alpha-2 like `US` or a check-host node id like `us1`). Value is the most recent per-region status.

Region status values:

- `ok` — the target returned an HTTP response within the timeout.
- `timeout` — the target did not respond within the timeout.
- `refused` — the target refused the TCP connection (commonly a provider-level block).
- `error` — a local client error made the measurement inconclusive. Not counted as a block.
- `blocked-inferred` — an operator-configured heuristic flagged the response as a block page rather than genuine traffic.

## Verdict rules

The verdict is recomputed every time a region update arrives. The rule set, using the hub-global `threshold_pct` (default 50):

- If `manual_block` is true, the verdict is `blocked`.
- Otherwise let F be the number of regions whose latest status is `timeout`, `refused`, or `blocked-inferred`, and let T be the total number of regions with any recorded status. `error` does not count toward F and does not count toward T.
- If T is zero (no usable measurements), the verdict is `unknown`.
- If F / T is at least `threshold_pct / 100`, the verdict is `blocked`.
- If F is zero and T is at least 1, the verdict is `live`.
- Otherwise the verdict is `degraded`.

The threshold is deliberately low enough to catch regional takedowns (a mirror blocked in two of four regions is already `blocked`) and high enough to tolerate a single flaky measurement node. Operators tune it in `/v1/settings/checkhost`.

## Manual overrides

An operator can hard-block a mirror to take it out of door rotation immediately, ahead of the automated poller noticing a regional block. This is the standard response to an incoming complaint or a suspicion that a mirror is burned.

Force-block:

```bash
curl -sS \
  --cert /etc/gateway/admin.crt --key /etc/gateway/admin.key \
  --cacert /etc/gateway/hub-ca.crt \
  -X POST \
  -d '{"note":"Provider complaint ticket 12345"}' \
  https://10.0.0.1:9080/v1/mirrors/mirror-3.your-domain.example/force-block
```

Remove the manual block (the verdict reverts to whatever the health data says):

```bash
curl -sS \
  --cert /etc/gateway/admin.crt --key /etc/gateway/admin.key \
  --cacert /etc/gateway/hub-ca.crt \
  -X POST \
  https://10.0.0.1:9080/v1/mirrors/mirror-3.your-domain.example/unblock
```

Manual blocks persist across hub restarts. They live in the same YAML record and are the only writable field operators touch directly (the others are derived from health data).

## How doors consume mirror health

Door slug selection reads the registry through the admin API (`GET /v1/mirrors`) on startup and then through the config stream for updates. The door's filter stack is: start with the full mirror list, drop mirrors whose verdict is not `live`, drop mirrors whose `tenants` list does not include the slug's target tenant (when the slug restricts tenants), drop mirrors with weight 0, drop mirrors listed under the slug's `exclude_regions` if any of their `regions` entries in those regions has status `refused` or `timeout`.

A mirror flipping from `live` to `blocked` is acted on at the next config-stream delta; doors that receive the delta adjust on the next request. There is no cached-selection state on doors, so a redirect that was computed before the delta is not retroactively voided; the client following the redirect simply hits the old mirror and succeeds or fails on its own. This is acceptable: the window is short and no slug reveals which mirrors are currently live.

## /v1/mirrors endpoints

The admin API routes are listed in full in `hub-api.md`; this section gives the operational view with examples.

List every mirror with its verdict:

```bash
curl -sS \
  --cert /etc/gateway/admin.crt --key /etc/gateway/admin.key \
  --cacert /etc/gateway/hub-ca.crt \
  https://10.0.0.1:9080/v1/mirrors | jq
```

Example response:

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
      "regions": {
        "us1": { "status": "ok",      "latency": 180 },
        "de1": { "status": "ok",      "latency": 220 },
        "ru1": { "status": "refused", "latency": 0 }
      }
    }
  ],
  "count": 1
}
```

Get one mirror:

```bash
curl -sS \
  --cert /etc/gateway/admin.crt --key /etc/gateway/admin.key \
  --cacert /etc/gateway/hub-ca.crt \
  https://10.0.0.1:9080/v1/mirrors/mirror-3.your-domain.example | jq
```

Register a mirror. Request body is the YAML record shown above, minus the derived fields (`verdict`, `last_check`, `regions`, `blocked_count`, `total_checked`). The hub fills those in.

```bash
curl -sS \
  --cert /etc/gateway/admin.crt --key /etc/gateway/admin.key \
  --cacert /etc/gateway/hub-ca.crt \
  -X PUT \
  -H 'Content-Type: application/yaml' \
  --data-binary @mirror.yaml \
  https://10.0.0.1:9080/v1/mirrors/mirror-3.your-domain.example
```

Trigger an immediate health pass across every mirror:

```bash
curl -sS \
  --cert /etc/gateway/admin.crt --key /etc/gateway/admin.key \
  --cacert /etc/gateway/hub-ca.crt \
  -X POST \
  -d '{"regions":["us1","de1","ru1"]}' \
  https://10.0.0.1:9080/v1/mirrors/check
```

Omit `regions` in the body to reuse the regions from `/v1/settings/checkhost`. A manual check is rate-limited at the hub to one run per 60 seconds; the limit applies across operators (no per-CN accounting) and exists to prevent accidental flood when two admins type `curl` at the same time.

Deregister:

```bash
curl -sS \
  --cert /etc/gateway/admin.crt --key /etc/gateway/admin.key \
  --cacert /etc/gateway/hub-ca.crt \
  -X DELETE \
  https://10.0.0.1:9080/v1/mirrors/mirror-3.your-domain.example
```

Deregistration removes the mirror from the registry and drops its file from `$HUB_DATA_DIR/runtime/mirrors/`. Any door that references the mirror through a slug's `target_tenants` continues to work; the mirror simply no longer exists as a selection candidate.

## Operational notes

Registering a new edge as a mirror is a two-step flow: the edge installer registers the node (`/v1/nodes/register` issues the mTLS cert), and then the operator registers the edge's public hostname as a mirror (`PUT /v1/mirrors/<host>`). These are separate because a node may host more than one public hostname (rare in practice but supported), and because not every node needs to be in door rotation (a test edge can be a registered node without being in the mirror registry).

Removing a mirror when an edge is burned is the mirror-registry operation. The node itself should also be revoked (`DELETE /v1/nodes/<id>`) if the edge is not coming back; the mirror record on its own does not invalidate the node's mTLS cert.

Mirror records do not carry secrets. Copying a mirror YAML between hubs is safe; it only describes public-facing state.

## Validation and reload

The mirror registry reload runs the same pattern as the tenant registry. On any file event under `$HUB_DATA_DIR/runtime/mirrors/` the hub re-reads every file, validates every record, and only on full success swaps the in-memory map. Validation checks:

- `host` is a valid DNS name and is unique across the registry.
- `tenants` entries all exist in the tenant registry (empty list is allowed).
- `weight` is a non-negative integer.
- `manual_block` is a boolean, `manual_note` is a string under 256 bytes.
- `regions` keys match the current `/v1/settings/checkhost` region list or are empty.

A validation failure aborts the reload with the failing file and field logged. The in-memory registry is unchanged; the previous snapshot continues to serve reads.

## Metrics

The hub publishes per-mirror counters alongside the existing tenant metrics:

- `gateway_mirror_verdict{host}` — gauge; 3 = live, 2 = degraded, 1 = blocked, 0 = unknown.
- `gateway_mirror_regions_failing{host}` — count of regions with status other than `ok` in the last pass.
- `gateway_mirror_check_duration_seconds{host}` — histogram of the full check-host round-trip per mirror.
- `gateway_mirror_manual_blocked` — gauge; total count of mirrors with `manual_block: true`.

Host labels on these metrics are not hashed. The mirror hostname is already public (it appears in every 302 from a door), so hashing it does not buy any OPSEC property. Operators who prefer opaque labels in dashboards can map host names to an internal id externally and filter on that.

## Relationship to tenant backends

A mirror fronts one or more tenants, and each tenant has its own list of `.onion` backends. The mirror registry is deliberately uninvolved in backend selection. An edge serving a tenant picks a backend with the existing tenant-backend logic (weighted negative-cache over the tenant's onion list); the mirror registry only answers the question "is this mirror reachable from region X." A blocked mirror on the hub's view does not tell the edge its backends are unreachable; it tells the door not to send new visitors to that mirror.

This split matters because it keeps the door and the edge as loosely coupled as possible. A door knows nothing about tenant backends. An edge knows nothing about doors. The hub is the only place where the two registries sit side by side, and even there they are separate files, separate admin endpoints, and separate validation paths.
