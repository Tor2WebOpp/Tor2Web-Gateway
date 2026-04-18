# Troubleshooting

Common failure scenarios and how to resolve them. Each entry follows
the same layout: symptom (what the operator sees), quick check
(commands to confirm the diagnosis), root causes, remediation.

For the install walkthrough see [`deployment.md`](deployment.md). For
the upgrade and rollback flows see [`upgrade.md`](upgrade.md).

## 421 Misdirected Request on every request

**Symptom.** Every public request returns
`HTTP/1.1 421 Misdirected Request` regardless of path.

**Quick check.**

```bash
curl -vk -H "Host: example.your-domain.example" https://edge-1.your-domain.example/
sudo journalctl -u gateway-proxy -p info --since "10m ago" | grep -i tenant
# Look for: tenant.loaded host=example.your-domain.example
```

**Root causes.**

1. Tenant not registered on the hub.
2. Tenant registered but the edge has not received the delta yet
   (transient race during a fresh install).
3. Client `Host` header does not match the tenant `host` field
   exactly after lowercasing.
4. Tenant `assigned_nodes` excludes this edge.

**Remediation.** For (1), register the tenant — see
[`deployment.md`](deployment.md#6-add-a-tenant). For (3), confirm the
`host:` field byte-matches the client `Host` after lowercasing. For
(4), check `assigned_nodes:` — the default `"*"` matches every edge.

## Admin URL returns 404

**Symptom.** The installer's admin URL returns 404 with empty body
and no `Content-Type`.

**Quick check.**

```bash
curl -vI https://hub.your-domain.example:9080/EXAMPLE-SLUG/EXAMPLE-TOKEN-A/EXAMPLE-TOKEN-B/
grep -A5 '^admin:' /etc/gateway/config.yaml
```

**Root causes.**

1. `admin.enabled: false` in `config.yaml`.
2. Slug or token in URL does not match the value in `config.yaml`
   (constant-time match returns 404 on any mismatch).
3. Operator IP is in soft-backoff or hard-banned state from earlier
   probes (defaults: 30s soft / 1h hard).
4. URL is missing the trailing slash.
5. Gate values were rotated by a re-installer run.

**Remediation.** For (1), set `admin.enabled: true` and ensure all
three fields are at least 32 characters; restart. For (2) and (5),
compare the URL byte-for-byte against `admin:` in `config.yaml`. For
(3), wait for the timer to expire or restart the binary to clear the
in-memory tracker. For (4), append the trailing slash. If the URL is
genuinely lost, see [I lost my admin tokens](#i-lost-my-admin-tokens).

## All requests 502

**Symptom.** Every public request returns 502 or 504. Edge logs show
`socks dial failed` or `no live backends`.

**Quick check.**

```bash
curl -sS http://10.0.0.1:9080/v1/health
sudo journalctl -u gateway-hub --since "5m ago" | grep -i tor
ps -ef | grep -E 'tor( |$)' | grep -v grep
```

**Root causes.**

1. Tor pool not finished bootstrapping (cold-start: 30-60s for first
   instance, 2-3min for `min_instances=4`).
2. Every Tor instance crashed (misconfigured `tor` binary, missing
   `data_dir`, port already in use).
3. Hub's wg interface is down; edge cannot reach `10.0.0.1`.
4. Edge `transport.hub_addr` is wrong.
5. Negative cache marked every backend cold after a real upstream
   incident (clears on its own; default TTL 5 minutes).

**Remediation.** For (1), wait — `/v1/health` shows `bootstrapping`
until ready. For (2), look at `pgrep -a tor`; common: `tor` not on
`$PATH`, `data_dir` not writable by `gateway`, `SOCKSPort` already
in use. For (3), restart `wg-quick@wg0` on both sides. For (5),
toggle the tenant `enabled: false` then `enabled: true` to clear
the cache for that tenant's backends.

## check-host.net returning 429

**Symptom.** Mirror verdicts flip to `unknown` and stay there. Hub
logs show `check-host: 429 Too Many Requests` on every poll cycle.

**Quick check.**

```bash
sudo journalctl -u gateway-hub --since "30m ago" | grep -c 'check-host: 429'
curl -sS -b cookies.txt "$HUB/$SLUG/$T1/$T2/api/settings/checkhost" | jq
```

**Root causes.**

1. `interval` too aggressive (defaults to 15 minutes; 1 minute
   against a fleet of 20 mirrors trips check-host's per-IP limit).
2. Hub's egress IP is shared with a noisy neighbour at the provider.
3. `regions` list too long (50 mirrors x 6 regions x 4/hour = 1200
   requests/hour from one IP).

**Remediation.** Raise `interval` and trim `regions`:

```bash
curl -sS -b cookies.txt -X PUT \
  -H "Content-Type: application/json" -H "X-CSRF-Token: $CSRF" \
  -d '{"interval":"30m","regions":["us1","de1","jp1"],"threshold_pct":50}' \
  "$HUB/$SLUG/$T1/$T2/api/settings/checkhost"
```

For (2), the only mitigation is moving the hub to a different egress
IP. check-host's rate limit is global per IP and there is no
API-key tier the gateway uses. See [`checkhost.md`](checkhost.md) for
the polling architecture.

## fsnotify not firing

**Symptom.** Operator drops a tenant YAML into
`$HUB_DATA_DIR/runtime/tenants/`; the hub does not pick it up. File
is present and readable; tenant absent from `GET /api/tenants`.

**Quick check.**

```bash
sudo -u gateway cat /var/lib/gateway/hub/runtime/tenants/example.your-domain.example.yaml | head
sudo journalctl -u gateway-hub --since "5m ago" | grep -E 'fsnotify|reload|tenant'
touch /var/lib/gateway/hub/runtime/tenants/example.your-domain.example.yaml
```

**Root causes.**

1. Filesystem does not propagate inotify events. Most common: btrfs
   subvolumes with `nodatacow`, bind-mounts inside Docker.
2. NFS mount (no inotify support; hub falls back to its 60-second
   poll cycle).
3. User inotify-watch limit exhausted (default 8192).
4. Editor wrote a `.swp` or `.tmp` rather than the final `*.yaml`.

**Remediation.** For (1), move `$HUB_DATA_DIR` to ext4 or xfs;
confirm with `inotifywait -m <dir>`. For (2), accept the 60-second
latency or move state off NFS. For (3):

```bash
sudo sysctl -w fs.inotify.max_user_watches=524288
echo 'fs.inotify.max_user_watches=524288' | sudo tee /etc/sysctl.d/40-inotify.conf
```

For (4), use `install` rather than the editor's tempfile flow:

```bash
sudo install -o gateway -g gateway -m 0640 \
  /tmp/example.your-domain.example.yaml \
  /var/lib/gateway/hub/runtime/tenants/example.your-domain.example.yaml
```

## WireGuard: no route to hub

**Symptom.** Edge cannot ping `10.0.0.1`. wg interface is up on both
sides but no traffic flows.

**Quick check.**

```bash
# On the edge:
sudo wg show wg0    # latest handshake within 2 minutes; transfer > 0
ping -c 3 -W 2 10.0.0.1

# On the hub:
sudo wg show wg0 peers   # edge's pubkey present with correct allowed-ips
```

**Root causes.**

1. Peer not configured on the hub (operator never ran the `wg set`
   line printed by the edge installer).
2. `AllowedIPs` mismatch (e.g. `10.0.0.0/24` instead of `10.0.0.42/32`).
3. UDP port 51820 blocked between edge and hub.
4. Edge's wg `Endpoint` points at the wrong hub address.
5. Both sides have the same wg public key (copy-paste mistake).

**Remediation.** For (1), run the printed `wg set` line on the hub:

```bash
sudo wg set wg0 peer EDGE_WG_PUBLIC_KEY allowed-ips 10.0.0.42/32
sudo wg-quick save wg0
```

For (3), switch to `transport=https_tunnel` (TCP `:8443`); requires
reinstalling both sides. For (5), regenerate the edge's wg key pair
and re-add the peer on the hub with the new pubkey.

## Session cookie rejected

**Symptom.** Browser keeps bouncing between a 302 and the admin URL;
address bar shows the slug and tokens repeatedly. No admin page
renders.

**Quick check.**

```bash
curl -sS -L -c cookies.txt -b cookies.txt -D - \
  "https://hub.your-domain.example:9080/EXAMPLE-SLUG/EXAMPLE-TOKEN-A/EXAMPLE-TOKEN-B/" \
  -o /dev/null
# Look for: single 302 followed by 200, with Set-Cookie: gw_adm=...
date -u
curl -sI https://hub.your-domain.example:9080/ | grep -i '^date:'
```

**Root causes.**

1. Admin URL is HTTP, not HTTPS. The gate sets `Secure: true`
   unconditionally; browsers refuse `Secure` cookies on plain HTTP.
2. Browser private window with cookies disabled for this origin.
3. Clock skew larger than 60 seconds between browser and hub
   (cookie's absolute-TTL fails).
4. Reverse proxy in front of the hub strips `Set-Cookie`, the
   `Secure` flag, the path attribute, or `HttpOnly`.

**Remediation.** For (1), install behind TLS — the production path
is public HTTPS in `socks5_tls` mode or SSH port-forward to a
trusted localhost. Curl works without TLS for diagnostics because
curl does not enforce `Secure`. For (3), run `chrony` or
`systemd-timesyncd` on both sides. For (4), configure the upstream
proxy to pass `Set-Cookie` and `Cookie` verbatim with no rewriting
of `Secure`, the cookie name, or the path.

## CSRF token mismatch on every mutation

**Symptom.** Every PUT, POST, PATCH, DELETE returns 403 with body
`{"error":"csrf"}`. GET calls succeed.

**Quick check.**

```bash
CSRF=$(curl -sS -b cookies.txt -D - \
  "$HUB/$SLUG/$T1/$T2/api/me" -o /dev/null \
  | awk -F': *' 'tolower($1)=="x-csrf-token"{print $2}' | tr -d '\r\n')
echo "CSRF=$CSRF"
sudo tail -n 5 /var/lib/gateway/hub/audit/$(date -u +%Y-%m-%d).jsonl
```

**Root causes.**

1. Client did not echo `X-CSRF-Token` at all.
2. Client cached an old token after a session refresh.
3. Reverse proxy stripped the `X-CSRF-Token` request header.
4. Cookie scope mismatch after a slug rotation.

**Remediation.** For (1), always read `X-CSRF-Token` from a
safe-method response before issuing a mutation; see
[`admin.md`](admin.md#csrf-flow) for the canonical pattern. For (2),
after a 403 on a mutation, re-read `/api/me` and retry once. For
(3), add `X-CSRF-Token` to the WAF's allow-list of forwarded headers.

## Binary crashes on startup

**Symptom.** `systemctl start` fails. Journal shows a Go panic, a
config error, or an `address already in use`.

**Quick check.**

```bash
sudo journalctl -u gateway-hub -n 100 --no-pager
sudo ss -tnlp | grep :9080
```

**Root causes.**

1. Config validation rejected a field (the message names it).
2. Required port already bound by another process.
3. `gateway` user cannot read config or write data dir.
4. mTLS CA key file missing or wrong mode (binary refuses to load
   anything other than `0600`).
5. `tor` binary not on `$PATH` (hub and local mode only).

**Remediation.** Common config diagnostics:

- `admin.slug too short` — needs 32+ characters when admin is enabled.
- `transport.kind invalid` — must be `wireguard`, `https_tunnel`,
  or `socks5_tls`.
- `tenants directory not readable` — `chown -R gateway:gateway` on
  `$HUB_DATA_DIR`.

Fix permissions:

```bash
sudo chown -R gateway:gateway /etc/gateway /var/lib/gateway /var/log/gateway
sudo chmod 0750 /etc/gateway /var/lib/gateway
sudo chmod 0640 /etc/gateway/config.yaml
sudo chmod 0600 /etc/gateway/hub-ca.key /etc/gateway/wg-hub-private.key
```

For (5), install `tor` and confirm with `which tor`.

## I lost my admin tokens

**Symptom.** Operator no longer has the admin URL.

**Quick check.** `sudo grep -A5 '^admin:' /etc/gateway/config.yaml`.
If the slug and tokens are present, reassemble:
`https://hub.your-domain.example:9080/<slug>/<token1>/<token2>/`.

**Remediation.** If `config.yaml` is also lost, regenerate on the
host (requires SSH):

```bash
sudo systemctl stop gateway-hub      # or gateway-proxy / gateway-door
SLUG=$(openssl rand -hex 16)
T1=$(openssl rand -hex 16)
T2=$(openssl rand -hex 16)
echo "slug:   $SLUG"; echo "token1: $T1"; echo "token2: $T2"

# Edit /etc/gateway/config.yaml — replace admin.slug, admin.token1,
# admin.token2 with the values above. Save and restart.
sudo systemctl start gateway-hub
```

The new URL takes effect on the next visit; old session cookies are
invalidated because the cookie path no longer matches. Rotation is
per-binary by design — rotating on a hub leaves edges and doors
unaffected. Record the new URL in the operator's secrets manager;
the installer's one-time print path is intentionally narrow.

## ACME challenge fails on a fresh edge

**Symptom.** First start of `gateway-proxy` fails to obtain a TLS
cert. Logs show `acme: HTTP-01 challenge failed`.

**Quick check.**

```bash
dig +short edge-1.your-domain.example
curl -v http://edge-1.your-domain.example/.well-known/acme-challenge/test
sudo ss -tnlp | grep ':80 '
```

**Root causes.**

1. DNS A/AAAA points at the wrong IP, or has not propagated.
2. Port 80 blocked at the firewall.
3. Another HTTP server already bound to port 80 (Apache or nginx
   default install on a fresh VPS).
4. ACME rate limit hit (Let's Encrypt: 50 certs per registered domain
   per week).

**Remediation.** For (1), fix the DNS record and wait out the TTL.
For (2), open port 80 in the cloud provider's firewall and any local
iptables. For (3), stop the conflicting service. For (4), use Let's
Encrypt's staging environment for development:

```yaml
acme:
  directory: https://acme-staging-v02.api.letsencrypt.org/directory
```

## Edge cannot register with hub

**Symptom.** Edge installer's mTLS step fails. Logs show
`POST /v1/nodes/register failed: 401 Unauthorized` or
`connection refused`.

**Quick check.**

```bash
ping -c 3 10.0.0.1
curl -sS http://10.0.0.1:9080/v1/health
grep node_secret /etc/gateway/config.yaml
```

**Root causes.**

1. wg tunnel is not up; registration runs over the same transport.
2. `node_secret` in edge config does not match the hub's expected
   value (manual edit can desync them).
3. Hub's CA is not initialized (hub install never completed).
4. Hub already has a node with the same `node_id`.

**Remediation.** For (1), restart `wg-quick@wg0` on both sides. For
(2), rerun the edge installer's registration step from scratch. For
(3), check the hub's logs at install time and rerun
`install-hub.sh`. For (4), deregister the old node first:

```bash
curl -sS -b cookies.txt -X DELETE \
  -H "X-CSRF-Token: $CSRF" \
  "$HUB/$SLUG/$T1/$T2/api/nodes/edge-1"
```

Then retry the edge registration.
