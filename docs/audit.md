# Admin audit log

The audit subsystem records every mutating admin action — and a few
diagnostic events such as CSRF rejections — to an append-only log on the
local node. P3 ships the storage and query API; the admin UI in P4 is
the consumer.

## What is logged

Every event carries the same shape:

```json
{
  "ts": "2026-04-18T12:34:56.123456789Z",
  "actor": "<session-id>",
  "actor_ip_hash": "<hex>",
  "node_id": "hub-main",
  "action": "tenant.upsert",
  "target": "shop.example",
  "diff": { "after": { "...": "..." } },
  "session_id": "<session-id>"
}
```

| Field           | Type                | Notes                                       |
|-----------------|---------------------|---------------------------------------------|
| `ts`            | RFC3339Nano string  | Server clock at write time                  |
| `actor`         | string              | Same as `session_id` for human admins       |
| `actor_ip_hash` | hex string          | SHA-256(client IP + per-install salt)       |
| `node_id`       | string              | The `node_id` from `config.yaml`            |
| `action`        | string              | `<resource>.<verb>` shape (see table below) |
| `target`        | string              | The mutated resource's identifier           |
| `diff`          | object, optional    | Pre/post snapshot, present on mutations     |
| `session_id`    | string, optional    | Echoes `actor` when set                     |

Actions logged in P3:

| Action            | Trigger                                 |
|-------------------|------------------------------------------|
| `tenant.upsert`   | `PUT /api/tenants/{host}` succeeded      |
| `tenant.delete`   | `DELETE /api/tenants/{host}` succeeded   |
| `globals.set`     | `PUT /api/globals` succeeded             |
| `feature.toggle`  | `POST /api/features/{name}/toggle` ok    |
| `session.logout`  | `POST /logout` or `POST /api/logout`     |
| `csrf.reject`     | Mutating request failed CSRF validation  |

Sessions issued by a fresh URL hit are not currently audited — the
P3 model treats the URL as the credential, so "successful entry"
is implied by every subsequent authenticated event. P4 may add an
explicit `session.start` event when the UI surfaces it.

## Log location and format

Files live under the configured `admin.audit_data_dir`. The default is
per-node-type:

- hub: `/var/lib/gateway/hub/audit`
- proxy: `/var/lib/gateway/proxy/audit`
- door: `/var/lib/gateway/door/audit`

Inside that directory:

```
<audit_data_dir>/
  audit/
    2026-04-18.jsonl    ← append-only daily file, mode 0600
    2026-04-19.jsonl
    audit.bolt          ← BoltDB index, mode 0600
```

Daily rotation happens automatically at UTC midnight. The append loop
calls `fsync(2)` after every event so a process crash never loses an
already-acknowledged write. The directory itself is created with mode
`0700` so only the gateway user can list contents.

`audit.bolt` is a small BoltDB store keyed on the 8-byte big-endian
nanosecond timestamp. The same JSONL payload that goes to disk is
duplicated into the index so query reads do not have to re-scan the
day-files. Two events sharing an exact nanosecond get a 2-byte sequence
suffix on their bolt key so the natural sort order is preserved
without losing rows.

## Query API

The admin handler exposes the log over the `/api/audit` route:

```
GET /<admin>/api/audit?since=<RFC3339>&limit=<int>
```

- `since` filters to events whose `ts` is strictly after the supplied
  timestamp. Omit for the full history.
- `limit` caps the response at N rows. Default 100, max 5000.

The response body is the JSON array of `Event` records, ordered
oldest-first. Example:

```sh
SLUG=...; T1=...; T2=...; HOST=https://hub.example:9080
curl -sS -b cookies.txt \
  "$HOST/$SLUG/$T1/$T2/api/audit?limit=10" | jq .
```

Programmatic consumers can also read the bolt index directly via the
admin package's `Log.Query(since, limit)` Go function — that is what
the API route uses internally.

## Rotation and retention

P3 does not delete old day-files. Operators must run their own cron job
or use a logrotate-style tool to expire entries beyond the retention
window. A typical setup keeps 30 days online and ships everything to
long-term storage:

```
# /etc/logrotate.d/gateway-audit
/var/lib/gateway/*/audit/audit/*.jsonl {
    daily
    rotate 30
    missingok
    notifempty
    nocompress
    nocreate
}
```

`nocreate` prevents logrotate from racing with the gateway binary on
the new day's file — the binary always opens it itself with `O_CREATE`
on first write. `nocompress` keeps the active file in plaintext so
the BoltDB index continues to point at the right rows; compress
yesterday's file as part of an out-of-band archival job that also
deletes the bolt-index entries that reference it.

The bolt index never expires entries on its own. To bound its growth,
operators should periodically copy `audit.bolt` to an archive,
delete it, and let the binary recreate the file on next write. The
index does not back-fill from the day-files, so any deletion is final
for query purposes — keep the day-files (or their archived copies)
as the source of truth.

A reasonable retention policy:

| Tier         | Window  | Storage                  |
|--------------|---------|--------------------------|
| Live         | 30 days | local disk, hot in bolt  |
| Warm archive | 1 year  | object store, gz of jsonl|
| Cold         | indef.  | offline backup           |

## OPSEC

Two rules govern what the audit subsystem accepts:

1. **No raw IPs**. Every `actor_ip_hash` is the output of the metrics
   labeler's `ClientIP(ip)` function — the same SHA-256(salt + ip)
   keyed on the per-install salt under
   `metrics.opsec.tenant_label_salt_file`. Operators correlating logs
   across nodes get stable hashes only when the salt is identical
   across the fleet; the installer enforces this.

2. **No raw hostnames in `diff`**. Tenant payloads carry the public
   `Host` already (operators need to know which tenant they edited),
   but any `.onion` backend, mirror hostname, or upstream URL inside
   the diff body is the responsibility of the writing handler — pass
   pre-hashed values where the spec calls for hashing, or omit them
   entirely.

The optional `RawLeakChecker` callback supplied via `OpenLogWithChecker`
runs synchronously inside `Write` before any disk or index mutation. A
non-nil error from the checker rejects the write outright. Operators
who maintain an explicit deny-list of strings that must never appear
(specific raw IPs, internal hostnames, secret bearer tokens) can install
the checker at boot and have the audit subsystem refuse the write
rather than silently leak.

What the audit log explicitly does NOT contain:

- Request bodies. Only the post-state of mutated resources via `diff`.
- Slug, token1, token2. The gate strips the prefix before the handler
  ever sees the path.
- Session cookies, CSRF tokens, mTLS client cert bytes. Sessions are
  recorded by ID only; the ID is high-entropy random and not derivable
  from the cookie value alone (the value IS the ID, but the ID is
  meaningless without the in-memory store).
- TLS server cert private key, hub CA private key, node-secret.
- Tor circuit identifiers, exit node IPs, .onion descriptors.
- User-agent strings, Referer headers, query parameters of arbitrary
  GET requests. Only mutating actions are audited.

When in doubt: the audit log is operator-readable, retained by default,
and may be shipped off-host. Anything that should not survive a backup
restore must not appear in a `diff`.
