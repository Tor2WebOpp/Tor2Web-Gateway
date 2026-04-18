# Deployment

This document is a linear walkthrough an operator can follow from a
freshly-installed Linux host to a multi-node production fleet. It covers
the hub, edge proxies, doors, transports, TLS, firewall rules,
observability, backups, and a final verification checklist.

For the architectural context that motivates the layout described here
see [`architecture.md`](architecture.md). For tenant configuration
schemas see [`tenants.md`](tenants.md), for individual feature parameters
see [`features.md`](features.md), and for the hub admin API used by all
the `curl` examples below see [`hub-api.md`](hub-api.md). After the
install is done, [`troubleshooting.md`](troubleshooting.md) collects the
common failure modes and [`upgrade.md`](upgrade.md) covers the upgrade
path between versions.

## 1. Prerequisites

Each host the gateway runs on must satisfy the following baseline. The
installer refuses to proceed if any of these is missing and prints the
exact package name for the detected distro.

- **Hardware.** Hub: 2 CPU, 4 GB RAM, plus one CPU per 8-10 Tor
  instances the operator plans to scale to. Edges and doors: 1 CPU
  and 512 MB RAM per node. Plan at least 1 GB of disk for
  `$HUB_DATA_DIR` (default `/var/lib/gateway/hub`) plus audit-log
  retention.
- **Operating system.** Linux x86_64 with systemd >= 245. Kernel >= 5.4
  for the `wireguard` transport. Tested on Debian 12 and Ubuntu 24.04;
  other systemd distros work but are out of the test matrix.
- **Tooling.** `bash >= 4.0`, `openssl`, `curl`, `tar` on every host.
  Go 1.22 or newer when building from source; release tarballs ship
  prebuilt static binaries and need no Go on the target.
- **Tor 0.4.x.** Required on the hub and on local-mode hosts; not
  required on edges or doors. The `tor` package on Debian and Ubuntu
  is sufficient.
- **WireGuard.** Install `wireguard` and `wireguard-tools` when
  `transport=wireguard` is selected (the default). Confirm the kernel
  module loads with `modprobe wireguard`.
- **Time sync.** Run `chrony` or `systemd-timesyncd` on every node.
  Clock skew larger than 60 seconds rejects session cookies during the
  admin gate's absolute-TTL check.

## 2. Decide topology

Single-box local mode runs `gateway-proxy` and `gateway-torpool` on
one host over a Unix socket. There is no hub, no mTLS, and no
WireGuard. Tenants live in a local directory the proxy watches
directly. This is the right shape when one host serves one or two
stable public domains and disposable edges are not needed.

Hub plus edges runs `gateway-hub` on a private host and any number of
`gateway-proxy` (and `gateway-door`) nodes facing the public internet.
The hub owns the tenant registry, the mTLS CA, the Tor pool, and the
mirror-health view; edges egress through the hub. This shape supports
rotating burnt edges, regional spread, doors as a cover layer, and
per-tenant isolation across multiple public domains.

| Property                     | Local | Hub + edges |
|------------------------------|-------|-------------|
| Public hosts per install     | 1     | N           |
| Disposable public surface    | no    | yes         |
| Per-tenant feature overrides | yes   | yes         |
| WireGuard required           | no    | optional    |
| mTLS CA on disk              | no    | yes (hub)   |
| Tor processes on public host | yes   | no          |
| Door redirector layer        | no    | optional    |
| Operational floor            | 1 host | 2 hosts    |

Pick local for a single domain on a single machine. Pick hub plus
edges in every other case. The rest of this document walks through
hub plus edges; the local-mode quickstart at the end condenses the
same flow.

## 3. Install the hub

Install the hub first. It owns the CA and tenant registry; edges
cannot register until the hub is running. Provision a host meeting
the prerequisites and open the firewall ports named in
[Firewall](#11-firewall). Then, as root:

```bash
git clone https://github.com/your-org/gateway.git /opt/gateway
cd /opt/gateway && git checkout v1.0.0
make build
sudo bash install-hub.sh
```

The interactive installer asks for: the hub's public hostname (used
in the wg endpoint line and the `https_tunnel`/`socks5_tls` URLs);
the transport kind (selecting `wireguard` makes the hub bind `:51820`
and generate a server key via `--wg-server`); the admin bind address
(default `10.0.0.1:9080`, the wg IP); and the data directory
(default `/var/lib/gateway/hub`, holding tenant YAMLs, mirror records,
audit log, TTL blocklist, and the CA key).

Non-interactive form (the only required flags are `--domain` and
`--yes`; everything else has a sensible default):

```bash
sudo bash install-hub.sh \
  --domain=hub.your-domain.example \
  --wg-server \
  --yes
```

The final step generates and writes to disk:

- `/etc/gateway/hub-ca.pem` — root CA cert; distribute to edges for
  TLS verification in `https_tunnel` and `socks5_tls` modes.
- `/etc/gateway/hub-ca.key` — root CA key, mode `0600`. Never copy
  off the hub.
- `/etc/gateway/wg-hub-private.key` — WireGuard private key (with
  `--wg-server`), mode `0600`.
- `/etc/gateway/metrics-salt` — 32-byte hex used for tenant-label
  and audit IP-hash.
- `/etc/gateway/config.yaml` — bootstrap config with admin slug and
  tokens.
- `/etc/systemd/system/gateway-hub.service` — copy of
  [`deploy/systemd/gateway-hub.service`](../deploy/systemd/gateway-hub.service).

The installer runs `systemctl daemon-reload` and
`systemctl enable --now gateway-hub`. Confirm with
`systemctl status gateway-hub` and `journalctl -u gateway-hub`.

The hub's admin URL is printed once in the form
`https://hub.your-domain.example:9080/EXAMPLE-SLUG/EXAMPLE-TOKEN-A/EXAMPLE-TOKEN-B/`.
Save it. The slug and tokens are also stored in `config.yaml` under
`admin:`; reassemble from there if the printed URL is lost. See
[`troubleshooting.md`](troubleshooting.md#i-lost-my-admin-tokens) if
`config.yaml` itself is lost.

Copy the CA cert where the edge installer can pick it up:

```bash
sudo cp /etc/gateway/hub-ca.pem /tmp/hub-ca.pem
chmod 644 /tmp/hub-ca.pem
# scp /tmp/hub-ca.pem operator@edge-1.your-domain.example:/tmp/hub-ca.pem
```

## 4. Install a proxy edge

On each edge host, as root:

```bash
git clone https://github.com/your-org/gateway.git /opt/gateway
cd /opt/gateway
git checkout v1.0.0
make build

# Interactive install. Asks every question the hub install does plus
# the edge-specific ones (hub address, mTLS CSR submission, admin slug).
sudo bash install.sh
```

The interactive installer walks through:

1. Node type — select `proxy`.
2. Public domain for this edge. Each edge should have its own domain
   and its own cert; the OPSEC model assumes public hosts do not
   correlate by certificate fingerprint.
3. Email for ACME registration.
4. Hub address. With `wireguard`, the hub's wg IP `10.0.0.1`; with
   `https_tunnel`, `https://hub.your-domain.example:8443`; with
   `socks5_tls`, `hub.your-domain.example:9443`.
5. Transport kind. Must match the hub.
6. WireGuard peer generation (`--auto-wg`). Installer generates the
   edge's key, prints the peer line for the hub once.
7. mTLS CSR generation. POSTs to `/v1/nodes/register`, writes the
   signed cert to `/etc/gateway/client.crt`.
8. Admin slug and two tokens, autogenerated.

Non-interactive form:

```bash
sudo bash install.sh \
  --type=proxy \
  --domain=edge-1.your-domain.example \
  --hub=10.0.0.1 \
  --transport=wireguard \
  --auto-wg \
  --admin-autogen \
  --yes
```

After the edge installer prints the WireGuard peer block, register
the peer on the hub. The installer prints the exact command:

```bash
# On the hub:
sudo wg set wg0 peer EDGE_WG_PUBLIC_KEY allowed-ips 10.0.0.42/32
sudo wg-quick save wg0
```

Verify the first request routes through:

```bash
# On the edge:
ping -c 3 10.0.0.1
curl -sS http://10.0.0.1:9080/v1/health
# {"status":"ok","tor_instances":4,"backends_live":4}

# Externally (after a tenant is configured per section 6):
curl -vk https://edge-1.your-domain.example/ -H "Host: example.your-domain.example"
```

A 200 response confirms TLS terminates on the edge, the request runs
through the middleware chain, the SOCKS dial reaches the hub via wg,
and the upstream `.onion` answers.

## 5. Install a door edge

A door serves a cover page on `/` and emits HTTP 302 on a small set
of opaque slug paths. See [`door.md`](door.md) for cover kinds, slug
routing, and selection strategies.

```bash
# On each door host, as root:
cd /opt/gateway
sudo bash install.sh --type=door
```

The interactive installer asks for the door's public domain (do not
share with an edge), an ACME email, the hub address and transport
kind (same as edges), an mTLS CSR with `node_type: door`, and a cover
asset (local file path copied under `/etc/gateway/cover/`, or
`passthrough_404` which serves an empty 404 with `Server: nginx`).

Non-interactive form:

```bash
sudo bash install.sh \
  --type=door \
  --domain=door-01.your-domain.example \
  --hub=10.0.0.1 \
  --transport=wireguard \
  --auto-wg \
  --cover-kind=static_file \
  --cover-path=/tmp/landing.html \
  --yes
```

Use a short DNS TTL (300 seconds is reasonable) so a burnt door can
be retired without long client-side caching. Register the door's
mirrors before publishing a slug — a slug pointing at a mirror set
with every verdict `unknown` returns 503.

Verify externally:

```bash
curl -I https://door-01.your-domain.example/
# Expect: 200 with the cover's content-type, or 404 for passthrough_404.

curl -I https://door-01.your-domain.example/EXAMPLE-SLUG
# Expect: 302 with a Location header pointing at a live mirror hostname.
```

Spread doors across providers. Slugs can be reused across doors
(stable user URL across rotations) or kept separate (burnt door does
not invalidate URLs published from others).

## 6. Add a tenant

A tenant is one public `Host` mapped to one or more `.onion` backends
plus its feature overrides. There are three ways to add one.

The first is via `curl` against the hub admin API. The full schema is
in [`tenants.md`](tenants.md); a minimal example:

```bash
SLUG="EXAMPLE-SLUG"
T1="EXAMPLE-TOKEN-A"
T2="EXAMPLE-TOKEN-B"
HUB="https://hub.your-domain.example:9080"

# Read the CSRF token first (mutating calls require it).
curl -sS -c cookies.txt -b cookies.txt -L \
  "$HUB/$SLUG/$T1/$T2/" -o /dev/null
CSRF=$(curl -sS -b cookies.txt -D - \
  "$HUB/$SLUG/$T1/$T2/api/me" -o /dev/null \
  | awk -F': *' 'tolower($1)=="x-csrf-token"{print $2}' | tr -d '\r\n')

# Upsert.
cat > /tmp/tenant.json <<'EOF'
{
  "host": "example.your-domain.example",
  "enabled": true,
  "backends": [
    {"addr": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion", "weight": 1}
  ]
}
EOF

curl -sS -b cookies.txt \
  -X PUT \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $CSRF" \
  --data-binary @/tmp/tenant.json \
  "$HUB/$SLUG/$T1/$T2/api/tenants/example.your-domain.example"
```

The second is via the admin web UI (P4). Open the admin URL in a
browser, navigate to **Tenants**, click **New tenant**, fill in the
host and the backend list, and save. The UI handles the CSRF token
automatically. See [`admin-ui.md`](admin-ui.md) for the page reference.

The third is by dropping a file into `$HUB_DATA_DIR/runtime/tenants/`.
The hub watches the directory with `fsnotify` and reloads on any
change. Use `install` (not `cp`) to ensure the hub never sees a
half-written file:

```bash
sudo install -o gateway -g gateway -m 0640 \
  /tmp/example.your-domain.example.yaml \
  /var/lib/gateway/hub/runtime/tenants/example.your-domain.example.yaml
```

The filename base must match the `host:` field inside the YAML.
Validation runs across the whole tenant set on every reload; any
failure aborts the swap and keeps the previous registry live. The
specific tenant and field that failed are logged.

## 7. Add a mirror

A mirror is a public hostname that fronts one or more tenants. Every
edge proxy is typically a mirror. The hub tracks reachability from
operator-chosen check-host.net regions; doors consult the resulting
verdict when picking a redirect target. See [`mirrors.md`](mirrors.md)
for the record shape and verdict rules.

```bash
cat > /tmp/mirror.yaml <<'EOF'
host: edge-1.your-domain.example
tenants: ["example.your-domain.example"]
weight: 1
manual_block: false
EOF

curl -sS -b cookies.txt -X PUT \
  -H "Content-Type: application/yaml" \
  -H "X-CSRF-Token: $CSRF" \
  --data-binary @/tmp/mirror.yaml \
  "$HUB/$SLUG/$T1/$T2/api/mirrors/edge-1.your-domain.example"

# Configure check-host regions once (defaults to us1, de1, ru1, jp1).
curl -sS -b cookies.txt -X PUT \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $CSRF" \
  -d '{"interval":"15m","regions":["us1","de1","jp1"],"threshold_pct":50}' \
  "$HUB/$SLUG/$T1/$T2/api/settings/checkhost"

# Trigger an immediate check to seed the verdict without waiting.
curl -sS -b cookies.txt -X POST \
  -H "X-CSRF-Token: $CSRF" -d '{}' \
  "$HUB/$SLUG/$T1/$T2/api/mirrors/check"

# Confirm.
curl -sS -b cookies.txt "$HUB/$SLUG/$T1/$T2/api/mirrors" \
  | jq '.mirrors[] | {host, verdict}'
```

A verdict of `live` means the mirror is eligible for door rotation.

## 8. Configure features

Every middleware capability has a global default and a per-tenant
override. Globals live in `$HUB_DATA_DIR/runtime/globals.yaml`; tenant
overrides live alongside the tenant YAML under `features:`.

Example `globals.yaml` that turns on rate-limiting and the regex
blocklist by default for every tenant:

```yaml
block_response:
  default: drop
  timeout_seconds: 30

features:
  blocklist_regex:
    enabled: true
    default_action: drop

  rate_limit:
    enabled: true
    per_ip_rps: 10
    per_ip_burst: 20

  ttl_blocklist:
    enabled: true
    default_ttl: 24h

  proxy_headers:
    strip_upstream: [Server, X-Powered-By, Via]
    add_downstream:
      - { name: X-Frame-Options, value: DENY }
      - { name: X-Content-Type-Options, value: nosniff }
```

Override per tenant by adding a `features:` block to the tenant YAML.
Setting a feature to `enabled: false` turns it off for that tenant
even if it is on globally. Setting a feature to `enabled: true` with
no parameters uses the global parameters but flips the toggle on.
Full schema and per-feature parameters in
[`features.md`](features.md) and [`tenants.md`](tenants.md).

Hot-reload behaviour. The hub watches both `globals.yaml` and the
tenants directory. On any change it re-reads every file, validates the
whole set across every tenant and every feature, and only on full
success swaps the in-memory registry. In-flight requests hold a
reference to the previous registry via context and finish on the old
config; subsequent requests pick up the new one. Edges receive the
delta over the config stream within a couple of seconds.

## 9. Enable admin UI on a proxy

The admin UI is embedded in every binary and served only through the
admin gate. It is on by default whenever the `admin:` block in
`config.yaml` has a slug and two tokens of at least 32 characters
each. The installer fills these in for every node.

Toggle the UI off on a specific node by flipping the gate:

```yaml
# /etc/gateway/config.yaml on the node:
admin:
  enabled: false
  slug: ""
  token1: ""
  token2: ""
```

Then `sudo systemctl restart gateway-proxy` (or `gateway-door`). With
`admin.enabled: false`, the gate code path runs against dummy buffers
so timing does not differ, and every request returns 404
indistinguishable from any unrouted path.

To enable the UI on a proxy when the installer left the gate off,
write a slug and two tokens of at least 32 characters each:

```yaml
admin:
  enabled: true
  slug: "EXAMPLE-SLUG"        # 32+ random chars
  token1: "EXAMPLE-TOKEN-A"   # 32+ random chars
  token2: "EXAMPLE-TOKEN-B"   # 32+ random chars
```

Restart and visit
`https://edge-1.your-domain.example/EXAMPLE-SLUG/EXAMPLE-TOKEN-A/EXAMPLE-TOKEN-B/`.
The first hit mints the session cookie and 302s to the trailing-slash
URL; from then on the cookie carries the auth.

## 10. TLS and certificates

Three certificate sources are involved. Confusing them is the most
common install-time mistake.

**Public TLS on edges and doors** is managed by CertMagic with ACME
HTTP-01 by default. CertMagic listens on port 80 alongside the public
HTTPS listener on 443; ACME challenges on `:80` answer without
entering the middleware chain. Certs live under
`/var/lib/gateway/certmagic/` and renew automatically 30 days before
expiry. The installer collects the ACME email address in step 4.

For custom certs (TLS-terminating proxy in front, internal CA), set:

```yaml
tls_cert_file: /etc/gateway/edge-1.crt
tls_key_file: /etc/gateway/edge-1.key
```

The presence of these fields disables ACME for that node. Files must
be readable by the `gateway` user; key files must be mode `0600`.

**Internal mTLS** between edges and the hub: the hub is the CA, edges
submit a CSR during install and store the signed cert at
`/etc/gateway/client.crt` and `/etc/gateway/client.key`. The hub's
root is at `/etc/gateway/hub-ca.pem`. The same pair authenticates
every edge call to the hub admin API. To rotate a cert in the P1
release, rerun the installer's registration step on the edge.

**Hub admin TLS** uses a self-signed cert at
`/etc/gateway/hub-admin.crt` when admin is bound to the wg overlay;
browsers warn unless the CA is imported. When the hub admin is bound
to a public hostname (`socks5_tls` binds `:9444` for admin), provide
a public-CA-signed cert via `hub.tls_cert_file` and
`hub.tls_key_file`.

## 11. Firewall

Open exactly the ports the role needs and no more.

| Role  | Inbound (TCP unless noted)          | Source       |
|-------|-------------------------------------|--------------|
| Hub (wg)         | 51820/UDP             | edge IPs     |
| Hub (https_tunnel) | 8443                | edge IPs     |
| Hub (socks5_tls) | 9443, 9444            | edge IPs     |
| Hub (any)        | 22                    | operator IPs |
| Proxy edge       | 80, 443               | 0.0.0.0/0    |
| Proxy edge       | 22                    | operator IPs |
| Door             | 80, 443               | 0.0.0.0/0    |
| Door             | 22                    | operator IPs |

The hub's admin API (`:9080`) and SOCKS5 listeners bind to `10.0.0.1`
in wg mode and must not be exposed to the public internet. Restrict
hub inbound to known edge IPs when possible.

Outbound on edges and doors: only to the hub on the configured
transport ports — UDP `:51820` for `wireguard`, TCP `:8443` for
`https_tunnel`, TCP `:9443` and `:9444` for `socks5_tls`. Doors
should be denied outbound to the SOCKS port range; doors do not
dial SOCKS, so cutting the path limits a compromised door's reach.

## 12. Observability

**Prometheus.** Each binary publishes a text endpoint when
`metrics.enabled: true`. Default bind is the wg overlay IP on hubs
and `127.0.0.1:9100` on edges. Bind to a private interface only.

```yaml
# prometheus.yml
scrape_configs:
  - job_name: gateway-hub
    static_configs:
      - targets: ['10.0.0.1:9100']
  - job_name: gateway-edge
    static_configs:
      - targets: ['10.0.0.42:9100', '10.0.0.43:9100']
```

Tenant labels are hashed by default with `metrics-salt`. Map a hash
back to a hostname via `/api/tenants` on the hub. Mirror labels are
not hashed (the hostname is already public in every door 302).

**Tracing.** OpenTelemetry exporters are configured under
`metrics.tracing`. See [`tracing.md`](tracing.md) for the trace shape.

```yaml
metrics:
  tracing:
    enabled: true
    otlp_endpoint: collector.your-domain.example:4317
    sampling_ratio: 0.05
    service_name: gateway-edge
```

**Audit log.** JSONL files written one per day under `<audit_data_dir>`
(default `/var/lib/gateway/<role>/audit/`). Schema in
[`audit.md`](audit.md). Rotate with `logrotate`:

```
# /etc/logrotate.d/gateway-audit
/var/lib/gateway/hub/audit/*.jsonl {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 gateway gateway
}
```

The hub opens a fresh file per day on its own; logrotate is for
historical-file compression and pruning, not for triggering new files.

**Systemd journal.** stdout and stderr go to the journal:
`journalctl -u gateway-hub -f` to follow live;
`journalctl -u gateway-proxy -p warning` for warnings and worse.

## 13. Backups

Back up the hub. Edges and doors are disposable.

On the hub, back up:

- `$HUB_DATA_DIR` (default `/var/lib/gateway/hub/`) — tenant and
  mirror registries, door runtime configs, audit log, TTL blocklist.
- `/etc/gateway/config.yaml` — bootstrap config with admin slug and
  tokens.
- `/etc/gateway/hub-ca.key` and `/etc/gateway/hub-ca.pem` — without
  these every edge re-registers after restore.
- `/etc/gateway/metrics-salt` — without it, existing audit IP-hashes
  are unmappable.

Daily cron example using `tar` and `gpg` for at-rest encryption:

```
# /etc/cron.daily/gateway-backup
#!/bin/sh
set -eu
TS=$(date -u +%Y%m%dT%H%M%SZ)
DST=/var/backups/gateway
GPG_RECIPIENT=ops@your-domain.example

mkdir -p "$DST"
tar -C / -czf - \
    var/lib/gateway/hub \
    etc/gateway/config.yaml \
    etc/gateway/hub-ca.key \
    etc/gateway/hub-ca.pem \
    etc/gateway/metrics-salt \
  | gpg --batch --yes --encrypt -r "$GPG_RECIPIENT" \
        -o "$DST/gateway-hub-$TS.tar.gz.gpg"

# Retain 30 days.
find "$DST" -type f -name 'gateway-hub-*.tar.gz.gpg' -mtime +30 -delete
```

Test the restore at least once: stop the hub, untar the archive over
`/`, `chown -R gateway:gateway /var/lib/gateway`, restart.

Edges and doors need no backup. A burnt edge is replaced by running
the installer on a fresh host; it re-registers with the hub and picks
up the tenant set from the config stream within seconds.

## 14. Verification checklist

Run after the install. Every command should succeed.

```bash
# Hub process up; admin endpoint answers; wg peers connected.
sudo systemctl is-active gateway-hub
curl -sS http://10.0.0.1:9080/v1/health
sudo wg show wg0 peers

# Edges up; each reaches the hub; ACME completed.
sudo systemctl is-active gateway-proxy            # on each edge
curl -sS http://10.0.0.1:9080/v1/health           # on each edge
sudo journalctl -u gateway-proxy --since "10m ago" | grep -i acme

# At least one tenant loaded; tenant resolves through the edge.
curl -sS -b cookies.txt "$HUB/$SLUG/$T1/$T2/api/tenants" | jq '.count'
curl -vk https://edge-1.your-domain.example/ \
  -H "Host: example.your-domain.example"

# At least one mirror live; door cover and slug both work.
curl -sS -b cookies.txt "$HUB/$SLUG/$T1/$T2/api/mirrors" \
  | jq '.mirrors[].verdict'
curl -I https://door-01.your-domain.example/
curl -I https://door-01.your-domain.example/EXAMPLE-SLUG

# Admin UI loads in a browser at the printed admin URL.
```

If any check fails, see [`troubleshooting.md`](troubleshooting.md)
for symptom-to-cause mappings.

## Local mode quickstart

```bash
sudo bash install.sh \
  --type=local \
  --domain=example.your-domain.example \
  --yes
```

The installer writes `/etc/gateway/config.yaml` (`mode: local`,
`node_type: local`), the two systemd units, and `/run/gateway/` for
the Unix socket. Tenant YAMLs go in `/etc/gateway/runtime/tenants/`
and the proxy watches them directly. The same tenant and feature
schemas apply; only the hub admin API and the config-stream channel
are missing.

## systemd reference

Each unit runs as the unprivileged `gateway` user. Shared hardening:
`ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`,
`NoNewPrivileges=yes`, `RestrictRealtime=yes`, `RestrictSUIDSGID=yes`,
`LockPersonality=yes`, `MemoryDenyWriteExecute=yes`, and a
seccomp filter (`SystemCallFilter=@system-service` minus
`@privileged @resources`).

`gateway-proxy.service` and `gateway-door.service` add
`AmbientCapabilities=CAP_NET_BIND_SERVICE` to bind 80 and 443 without
root. `gateway-torpool.service` does not need this — Tor binds no
privileged ports — and creates its socket under `/run/gateway/` via
`RuntimeDirectory=gateway`.

`gateway-hub.service` adds `ReadWritePaths=/var/lib/gateway` and an
`After=wg-quick@wg0.service` dependency when wg transport is selected,
ensuring the overlay is up before the hub binds its admin listener.
The full unit lives at
[`deploy/systemd/gateway-hub.service`](../deploy/systemd/gateway-hub.service).

Restart with `systemctl restart gateway-<role>`. Runtime config
changes do not need a SIGHUP — fsnotify drives reloads on the hub
and the config stream propagates to edges.

## Uninstall

```bash
sudo systemctl disable --now \
  gateway-proxy gateway-torpool gateway-hub gateway-door \
  wg-quick@wg0 2>/dev/null || true
sudo rm -f /etc/systemd/system/gateway-*.service
sudo systemctl daemon-reload
sudo rm -rf /etc/gateway /var/lib/gateway /run/gateway /var/log/gateway
sudo userdel gateway 2>/dev/null || true
```

This removes everything including the tenant registry and the CA key.
Back up `/var/lib/gateway/hub/` first if the intent is to reinstall
with the same tenants. See [`upgrade.md`](upgrade.md) for the
upgrade-in-place flow that preserves state.
