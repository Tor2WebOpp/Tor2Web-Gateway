# check-host.net integration

check-host.net is a public third-party service that runs on-demand network checks (HTTP, TCP, DNS, ping) from a set of distributed probe nodes. The hub uses its HTTP endpoint to poll mirror hostnames from regions the operator does not have nodes in, so the mirror-health registry reflects what a visitor in those regions would see rather than what the hub sees from its own location. This is what makes the `blocked` verdict accurate for regional takedowns: the hub in Germany may be able to reach a mirror fine while a probe in Russia or China refuses the connection, and the operator learns about the block without running probes in those countries themselves.

The integration is strictly one-way. The hub calls check-host.net; check-host.net never calls the hub. No check-host.net identifier is stored on the hub, and no tenant or backend information is sent to check-host.net. The only data the hub sends is the mirror hostname (which is public) and the list of probe regions (which is operator-chosen config).

## API endpoints used

Two endpoints are consumed. Both are documented at `https://check-host.net/about/api`.

`POST https://check-host.net/check-http?host=<mirror>&max_nodes=<N>`

Starts a check. The hub issues this call with the mirror's public hostname. `max_nodes` defaults to 4; operators raise it to widen regional coverage at the cost of more per-minute API usage. The response returns a `request_id` and the list of node ids chosen for the check. Example response body:

```json
{
  "ok": 1,
  "request_id": "abc123",
  "permanent_node_id": "us1.node.check-host.net",
  "nodes": {
    "us1.node.check-host.net": ["United States", "New York", "Some provider"],
    "de1.node.check-host.net": ["Germany", "Frankfurt", "Some provider"],
    "ru1.node.check-host.net": ["Russia", "Moscow", "Some provider"]
  }
}
```

`GET https://check-host.net/check-result/<request_id>`

Polls for the result. Each node reports a list of per-attempt outcomes. An HTTP check result per node is a four-element array `[ok, time_seconds, body_bytes, response_headers]`; an absent array means the node has not finished yet. The hub polls every 5 seconds up to 60 seconds, then gives up and marks the unfinished regions `error` (not `timeout`, because the measurement itself did not complete).

Example response body:

```json
{
  "us1.node.check-host.net": [[1, 0.18, 2048, "HTTP/1.1 200 OK"]],
  "de1.node.check-host.net": [[1, 0.22, 2048, "HTTP/1.1 200 OK"]],
  "ru1.node.check-host.net": [[0, null, null, "Connection refused"]]
}
```

The hub normalizes each node's result into a `RegionStatus` record on the matching mirror. Status mapping:

- First array element is 1 and response header starts with `HTTP/` → `ok`, with `latency` set to `time_seconds * 1000`.
- First array element is 0 and the response string contains `refused` → `refused`.
- First array element is 0 and the response string contains `timeout` or `timed out` → `timeout`.
- Any other result where the first element is 0 → `error`.
- The node returned but the response looks like a known block page (matched against the operator-configured `block_patterns` list, if set) → `blocked-inferred`.

## Rate limits

check-host.net does not publish a hard rate limit. Practical experience shows sustained use above 1 request per 5 seconds per source IP starts returning HTTP 429 with a `Retry-After` header. The hub honors `Retry-After` exactly; if the header is missing, the hub backs off exponentially starting at 5 seconds and doubling up to 120 seconds. Exceeding this ceiling marks the current run failed and retries at the next scheduled interval.

The hub's worker runs one check at a time. With 10 mirrors and a 5-second floor between calls, a full pass takes about 50 seconds of API time plus the poll-for-result window per mirror. Operators should size the scheduled interval with this in mind (default is 15 minutes, which leaves plenty of slack).

Two hub-global settings shape outbound pacing:

- `interval` — time between scheduled runs (default `15m`).
- `min_request_spacing` — floor between API calls inside a run (default `5s`).

Both are read from `/v1/settings/checkhost` and applied on the next run.

## Region selection

The default region list is empty. When the list is empty, the hub does not call check-host.net at all and all mirrors remain `unknown` until either the operator provides regions or a manual block is set. This default is deliberate: an operator who installs the hub should make a conscious choice about which regions to monitor, rather than the hub silently fanning out to arbitrary nodes.

Regions are specified as check-host.net node ids. The full list is available at `https://check-host.net/nodes/hosts`; common examples include `us1`, `de1`, `nl1`, `ru1`, `ir1`, `cn1`. Operators typically pick a small set that covers their audience: two to four regions for most deployments, six for geographically spread audiences.

Settings example:

```bash
curl -sS \
  --cert /etc/gateway/admin.crt --key /etc/gateway/admin.key \
  --cacert /etc/gateway/hub-ca.crt \
  -X PUT \
  -H 'Content-Type: application/json' \
  -d '{"enabled":true,"interval":"15m","regions":["us1","de1","nl1","ru1"],"threshold_pct":50,"max_nodes":4}' \
  https://10.0.0.1:9080/v1/settings/checkhost
```

Reading current settings:

```bash
curl -sS \
  --cert /etc/gateway/admin.crt --key /etc/gateway/admin.key \
  --cacert /etc/gateway/hub-ca.crt \
  https://10.0.0.1:9080/v1/settings/checkhost | jq
```

Example response:

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

## Interval tuning

The scheduled interval is per-hub and applies to every registered mirror. A shorter interval means faster detection of a regional block at the cost of higher API usage. Recommended defaults by fleet size:

- Small (up to 5 mirrors): 15 minutes. A full pass takes under a minute; the hub spends most of its time idle.
- Medium (5 to 20 mirrors): 15 minutes to 30 minutes depending on region count.
- Large (20+ mirrors) or high region count: 30 minutes or longer. Use the `POST /v1/mirrors/check` endpoint for immediate checks when an operator suspects a block.

Per-minute API cost approximation: one `check-http` POST plus roughly five `check-result` GETs per mirror per run, multiplied by the pass count per hour. At 10 mirrors on a 15-minute interval with 5 polls each, this is 10 + 50 = 60 API calls per 15 minutes, or 4 per minute on average. Well under any practical ceiling.

## Threshold_pct and false positives

Transient node failures on check-host.net are common. A single node reporting `refused` while three others report `ok` is usually a flaky probe, not a real block. `threshold_pct` handles this by requiring a fraction of regions to agree before calling the mirror blocked.

The default of 50 means more than half the regions must report `refused` or `timeout` before the verdict is `blocked`. With 4 regions this is 3 or more failing. With 2 regions it is both; operators using only 2 regions should raise the threshold above 50 (say, 75) to require both, or drop below 50 (25) to flip to blocked on a single regional failure. Fewer than 2 regions is not recommended because the verdict space collapses.

A mirror that is `degraded` (some but not enough regions failing) remains in door rotation. The door's `exclude_regions` filter can still drop the mirror for slugs that target those regions; the verdict is about whether the mirror is globally usable, not whether it should be served to a specific country.

## Caveats

check-host.net is a third party with its own uptime and its own threat model. The hub treats it as an information source, not a source of truth. A `blocked` verdict from a check-host.net pass is useful signal but not proof; operators who care deeply about why a mirror is blocked run their own probes from their own vantage points and compare.

check-host.net's probe nodes are known public IPs. A backend or CDN that blocks check-host.net IPs will cause `refused` across all regions, producing a `blocked` verdict even when real visitors have no problem. Operators who see this pattern should verify from another source before rotating the mirror out. The `error` status (used when the measurement itself fails) is a partial mitigation: if check-host.net reports a node-side error rather than a downstream result, that counts as `error` and does not advance the verdict toward `blocked`.

check-host.net does not test from every country the operator might care about. The node list is biased toward data centers in Europe, North America, and a handful of other regions. If the operator's audience is primarily in a country with no check-host.net node, the integration is of limited value and manual probes from a small cheap VPS in the target region are the substitute.

The integration can be disabled entirely with `enabled: false` in `/v1/settings/checkhost`. In that state, verdicts are driven solely by manual blocks; every mirror without a manual block stays `unknown`, and every slug's strategy filter treats `unknown` mirrors the same as `degraded` ones (in rotation, but not preferred). This is the correct configuration for operators who either distrust third-party probes or run their own probe infrastructure they prefer to feed the registry from.

## Block-pattern detection

Some providers serve a plausible-looking HTML page instead of refusing the connection when a site is blocked upstream. Such "soft blocks" return HTTP 200 and defeat the naive `refused`/`timeout` check. The hub supports an optional list of `block_patterns` on the checkhost settings: regex strings tested against the response body seen by each probe. A match flips that region's status to `blocked-inferred`, which counts toward the threshold the same as `refused`.

Example settings with a pattern list:

```json
{
  "enabled": true,
  "interval": "15m",
  "regions": ["us1", "de1", "ru1"],
  "threshold_pct": 50,
  "max_nodes": 4,
  "block_patterns": [
    "(?i)the information resource is blocked",
    "(?i)access to this resource is restricted"
  ]
}
```

The hub compiles each pattern at settings update and rejects the update if any pattern fails to compile. Matching is done against the first 4 KB of the response body that check-host.net returns; responses larger than 4 KB are truncated before the match for cost control. Operators should keep this list short: every pattern runs on every probe response across every mirror, and patterns with backtracking regex can get slow.

## Operator workflow

A typical day-one configuration flow after a hub is up:

1. Pick 2-4 regions that cover the intended audience.
2. `PUT /v1/settings/checkhost` with those regions, threshold 50, interval 15 minutes.
3. Register the edges as mirrors (`PUT /v1/mirrors/<host>` per edge).
4. Wait one interval for the first pass. `GET /v1/mirrors` should show `verdict: live` for every entry.
5. Trigger a manual pass against a test region that is known to block the content (if one is available). Verify that mirror transitions to `blocked`.
6. Unblock the mirror (or adjust the threshold if the probe was flaky), and verify the mirror returns to `live`.

Once this loop works, register the first door and point a slug at the live mirrors. The pieces are loosely coupled enough that each step can be validated independently; the integration is only "live" from the door side once every upstream piece is working.

## Failure modes and responses

check-host.net returns 5xx or times out — the hub retries the run at the next interval; the mirror's `last_check` timestamp does not advance. If `last_check` gets stale (more than 3 intervals old), operators see a gauge `gateway_checkhost_stale_mirrors_total` tick up in metrics.

check-host.net returns HTTP 429 with a `Retry-After` — the hub honors the header exactly and defers the next run until the header's deadline has passed. The interval schedule catches up on its own; there is no backlog that needs clearing.

check-host.net returns a malformed JSON body — logged at WARN with the request id; the specific pass is discarded and the mirror's prior verdict remains.

A probe node itself is down (no result for the pass) — the region is marked `error`, which does not count toward the block threshold. If this persists, operators swap the region id for a nearby alternate.

The hub cannot reach check-host.net at all (DNS, routing, firewall) — every mirror's `last_check` stops advancing. After 3 intervals, mirrors with no manual block flip to `unknown` and doors derank them; this is intentional so that a broken probe path does not let stale verdicts linger as `live`.

## Outbound whitelist

The hub's egress whitelist in `internal/proxy/egress.go` must include `check-host.net` when the integration is enabled. The hub installer handles this automatically when the operator enables the feature at install time; manual enablement through the admin API does not modify the whitelist, and operators who enabled check-host on a hub that was installed with the feature off need to add `check-host.net` to the whitelist by hand. A request to check-host.net from a hub with the feature enabled but the whitelist missing the entry fails with an egress-policy error logged at ERROR level; the integration stays disabled until the whitelist is updated and the hub is restarted.

The whitelist is deliberately restart-only. Hot-reloading the egress allow-list is out of scope in P2; the decision to bake it into binary startup means operators cannot flip it on remotely through a compromised admin credential.
