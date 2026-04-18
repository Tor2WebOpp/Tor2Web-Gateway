# Upgrade

This document covers the upgrade flow from one gateway release to the
next, the rollback procedure when an upgrade misbehaves, and the
one-time migration from a pre-P1 single-process deployment to the
current multi-tenant layout.

For the install walkthrough see [`deployment.md`](deployment.md). For
post-upgrade issues see [`troubleshooting.md`](troubleshooting.md).

## Breaking-change policy

The 0.x series follows semver loosely: minor versions
(`0.1.0` → `0.2.0`) may change config-schema field names or remove
deprecated fields; patch versions are binary-and-config compatible.
Any breaking change is called out in the release notes.

P1 through P5 ship as a single 0.x release line with no schema breaks
between phases — a `config.yaml` written by the P1 installer loads
unchanged in the P5 binary. The 1.0.0 release will mark the first
stable schema. Until 1.0, treat every upgrade as potentially breaking.

## Upgrade from current to next minor

The flow assumes one hub and at least one edge. Doors follow the same
pattern as edges. Local-mode hosts are the single-binary version.

### Step 1: read the release notes

Each release ships notes under `docs/releases/<version>.md`. Read the
**Schema changes** section (flagged with the exact field path),
**Feature flips** (new defaults), and **Database migrations** (the
audit-log BoltDB index versions automatically on first start).

### Step 2: back up the hub

Run an out-of-cycle backup:

```bash
sudo tar -C / -czf /var/backups/gateway/pre-upgrade-$(date -u +%Y%m%dT%H%M%SZ).tar.gz \
    var/lib/gateway/hub \
    etc/gateway/config.yaml \
    etc/gateway/hub-ca.key \
    etc/gateway/hub-ca.pem \
    etc/gateway/metrics-salt
```

Confirm the archive size is in line with previous backups; a much
smaller archive often means earlier truncation.

### Step 3: upgrade the hub

```bash
# On the hub:
cd /opt/gateway
sudo systemctl stop gateway-hub

git fetch && git checkout v0.2.0
make build
sudo install -o root -g root -m 0755 \
    bin/gateway-hub /usr/local/bin/gateway-hub

# Refresh the systemd unit if the release ships changes:
sudo install -o root -g root -m 0644 \
    deploy/systemd/gateway-hub.service \
    /etc/systemd/system/gateway-hub.service
sudo systemctl daemon-reload

sudo systemctl start gateway-hub
curl -sS http://10.0.0.1:9080/v1/health
```

If the hub crashes on startup, see
[Binary crashes on startup](troubleshooting.md#binary-crashes-on-startup)
and roll back if needed.

### Step 4: upgrade edges one at a time

Drain by setting the mirror to `manual_block: true`:

```bash
curl -sS -b cookies.txt -X PUT \
  -H "Content-Type: application/yaml" -H "X-CSRF-Token: $CSRF" \
  -d 'host: edge-1.your-domain.example
tenants: ["example.your-domain.example"]
weight: 0
manual_block: true
manual_note: "draining for upgrade"' \
  "$HUB/$SLUG/$T1/$T2/api/mirrors/edge-1.your-domain.example"
```

Doors stop sending new traffic on the next config-stream delta
(within seconds). Wait ~60s for in-flight requests, then upgrade:

```bash
# On the edge:
cd /opt/gateway
sudo systemctl stop gateway-proxy
git fetch && git checkout v0.2.0
make build
sudo install -o root -g root -m 0755 \
    bin/gateway-proxy /usr/local/bin/gateway-proxy
sudo systemctl daemon-reload
sudo systemctl start gateway-proxy

# Verify and re-add to rotation.
curl -sS http://10.0.0.1:9080/v1/health
curl -sS -b cookies.txt -X POST \
  -H "X-CSRF-Token: $CSRF" \
  "$HUB/$SLUG/$T1/$T2/api/mirrors/edge-1.your-domain.example/unblock"
```

Apply the same flow to doors. Order matters: hub first, then edges
and doors. Edges built against an older hub schema may fail to
register if the hub already speaks the new schema.

## Config migration notes

P1 through P5 ship as one release line with no breaking schema
changes. A config written by the P1 installer is accepted unchanged
by every subsequent phase binary. New fields per phase:

| Phase | New top-level fields                              | Default |
|-------|---------------------------------------------------|---------|
| P2    | `mirrors:`, `door:` (per-binary)                  | empty registry; no doors |
| P3    | `admin.session_idle_ttl`, `admin.session_absolute_ttl`, `admin.lockout.*`, `admin.audit_data_dir` | 15m / 8h / soft 3-in-60s |
| P4    | None (UI assets embedded at build time)           | same as P3 |
| P5    | None (docs and i18n catalogs only)                | same as P4 |

Operators upgrading from P1 to P5 in one step do not need to edit
`config.yaml` at all. The P5 binary fills new defaults on first load
and writes them back only if the operator subsequently mutates the
file via the admin UI or API.

## Rollback

```bash
# On the hub:
sudo systemctl stop gateway-hub
cd /opt/gateway && git checkout v0.1.0 && make build
sudo install -o root -g root -m 0755 \
    bin/gateway-hub /usr/local/bin/gateway-hub
sudo systemctl daemon-reload

# Optionally restore the data directory:
sudo tar -C / -xzf /var/backups/gateway/pre-upgrade-<TIMESTAMP>.tar.gz
sudo systemctl start gateway-hub
```

Edges and doors roll back the same way: stop, swap binary, restart.
They have no on-disk state beyond the mTLS client cert (stable across
upgrades). A rollback that restores `$HUB_DATA_DIR` discards any
tenant or mirror changes made between backup and rollback; re-apply
those after the rollback completes.

## Phase-to-phase upgrade from pre-P1 to P1

One-time migration from the original single-process deployment (one
host, flat single-tenant config) to the multi-tenant layout. There
is no in-place upgrade path that keeps the old single-process layout
— separating the public surface from Tor egress is the whole point
of remote mode, and the migration is explicit by design.

**Step 1.** Provision a fresh host for the hub (the old gateway
machine cannot double as the hub). Run the hub install per
[`deployment.md`](deployment.md#3-install-the-hub). Carry over the
old Tor settings (`min_instances`, `max_instances`,
`socks_base_port`).

**Step 2.** Convert the existing gateway machine into an edge:

```bash
cd /opt/gateway
git fetch && git checkout v0.1.0
make build
sudo bash install.sh --type=proxy
```

The installer detects the pre-P1 `/etc/gateway/config.yaml`, offers
conversion, and on accept preserves the old file as
`config.yaml.pre-p1`, writes a fresh edge config pointing at the
hub, and runs the mTLS and wg flows as for any fresh edge.

**Step 3.** Write the single tenant as a YAML file on the hub:

```bash
cat > /tmp/example.your-domain.example.yaml <<'EOF'
host: example.your-domain.example
enabled: true
backends:
  - addr: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
    weight: 1
EOF
sudo install -o gateway -g gateway -m 0640 \
    /tmp/example.your-domain.example.yaml \
    /var/lib/gateway/hub/runtime/tenants/example.your-domain.example.yaml
```

**Step 4.** Verify the new edge serves the tenant, then stop the
pre-P1 torpool on the old machine:

```bash
curl -vk https://edge-1.your-domain.example/ \
  -H "Host: example.your-domain.example"
sudo systemctl stop gateway-torpool-prep1
sudo systemctl disable gateway-torpool-prep1
```

For multiple pre-P1 instances on separate hosts, repeat per host:
each old machine becomes one edge, each domain becomes one tenant
YAML. After migration, any edge can serve any tenant — one of the
main benefits of remote mode.

Doors are additive and not part of this migration. Run the door
installer ([`deployment.md`](deployment.md#5-install-a-door-edge))
at any point after the hub is up.
