# OPSEC model

This document describes what the gateway protects against, what it does not, and the hardening steps recommended for operators. It is deliberately concrete: every protection below is implemented somewhere in the code or infrastructure, and every non-protection is called out so operators do not assume a property the software does not provide.

## Threat model

The gateway is designed for a situation where:

1. The public hosts (edges) are expected to be discovered and attacked. They are disposable: an edge that is blocked or compromised is thrown away and replaced.
2. The hub is private. It should never be reachable from the public internet except over the transport the operator chose (wg, https-tunnel, or socks5-tls).
3. The tenant backends are `.onion` services the operator wants to expose through clearnet-fronting mirrors without the backends themselves being reachable from clearnet directly.
4. The adversary may: enumerate hosts, scrape traffic, send malicious requests, correlate edges via shared identifiers, de-anonymize the operator via leaked metadata, or exploit a vulnerability on one edge to pivot to the hub.

Against this model, the gateway aims for three things: edge disposability (an edge compromise does not compromise the hub or other edges), minimized metadata (logs, metrics, certs, and error messages do not correlate edges), and no outbound leak (edges do not phone home).

The gateway does not aim to defend against a network-level observer who controls both the client network and the edge's uplink (they can correlate traffic regardless). It does not aim to hide the existence of the edges; it aims to limit what the existence of a given edge reveals about other edges and the hub.

## What is protected

### Tenant identifier confidentiality in metrics

Tenant labels in Prometheus metrics are `sha256(host + salt)[:16]`. The salt lives in `/etc/gateway/metrics-salt`, generated once per install with 32 bytes of randomness. A metrics scraper cannot reverse the hash without the salt. If the salt is missing at start time, metrics collection refuses to start rather than silently emit raw hostnames.

Configuration:

```yaml
metrics:
  enabled: true
  listen: "10.0.0.42:9090"
  opsec:
    hash_tenant_labels: true
    tenant_label_salt_file: /etc/gateway/metrics-salt
```

Operators who need raw hostnames (for debugging, grafana dashboards) read them from the hub admin API, not from `/metrics`. The admin API lives on the private transport and requires mTLS.

### Client IP anonymization in logs

All log lines that include a client IP route through a single `anonymize_ip` helper. For IPv4, the last octet is zeroed. For IPv6, the last 64 bits are dropped. The helper is invoked by every middleware's logger and by the reverse-proxy access log. Any direct string-construction of an IP in a log line is a bug and should fail code review.

Configuration:

```yaml
logging:
  anonymize_ips: true
```

Abuse reports use a stronger anonymization. The client IP is hashed with the metrics salt (`sha256(ip + salt)[:16]`), not masked. This lets operators cluster reports by source without learning the source.

### Admin surface is not logged and not advertised

The admin gate prefix (`/<slug>/<token1>/<token2>/`) is never logged. The logging middleware has a filter that strips matching paths before the request object reaches the access logger. Error pages returned from paths under the admin prefix do not include the requested path in their body.

The slug and tokens are printed to stdout exactly once by the installer, in a block clearly marked "save this now". They are never written to a log file, never sent to the hub, and never displayed in any UI. Operators who lose them must regenerate them and propagate the new values manually.

### No outbound telemetry or update checks

Edges make no outbound network calls except two:

1. To the hub, via whichever transport was configured.
2. To tenant backends, via SOCKS5 through the hub's Tor pool.

There is no update check, no crash reporting, no analytics, no "phone home on start", no NTP (system clock is the OS's responsibility), no DNS beyond what the OS resolver does for tenant `Host` lookups (which happen client-side; edges do not resolve anything).

Any attempt to add a new outbound caller must be whitelisted in `internal/proxy/egress.go`. CI enforces this with a grep for `net.Dial`, `http.Client`, and similar primitives outside whitelisted paths.

### Per-edge TLS certificates

Each edge gets its own TLS certificate, issued by ACME against its own public hostname. There is no shared cert across edges. This means a public scan that correlates TLS fingerprints (certificate SHA-256, ALPN, ja3) will not immediately cluster all edges together unless the fingerprint itself is derived from a shared template.

The installer goes one step further: ACME accounts are per edge. Two edges do not share an ACME registration email or account key, so an adversary who obtains Let's Encrypt's account-to-cert mapping (unlikely but possible through transparency-log analysis) still needs per-account correlation work.

Hub-side TLS, by contrast, does use a shared CA (the hub CA). This is by design: the CA is private and never leaves the hub, and the edges' client certs are seen only by the hub across the private transport.

### mTLS authorization with CRL

Every edge-to-hub call is authenticated by an mTLS client cert with CN == `node_id`. The hub validates the cert against its CA on every TCP connection, and against the CRL on every 60-second reload. Revoked certs cannot reconnect; their existing connections close on the next heartbeat and the edge stops serving new traffic after the `grace_seconds` window.

Certificates are bound to a single edge. Copying a cert to another machine does not grant that machine edge access because the peer's wg IP (in wireguard transport) must also match the registered allocation. The hub rejects a cert whose source address is not on the allow-list for that CN.

### Admin gate timing

The admin-gate prefix match uses `subtle.ConstantTimeCompare` across all three segments regardless of which segment mismatched. The match function never returns early on first mismatch. This property is required in P1 so that when P3 lands the real admin handler, the timing side-channel is already closed. Adversaries probing the path cannot distinguish "first segment wrong" from "third segment wrong" via response time.

### Door slug timing

The door's slug matcher runs `subtle.ConstantTimeCompare` against every configured slug on every request whose first path segment looks like a candidate. Iteration does not short-circuit on match; the loop runs to completion and the matching slug, if any, is retained. A prober who sends `/AAAAAAAA...` and `/BBBBBBBB...` cannot learn which slug (if any) matched by timing the responses.

When no slug matches, the request is routed to the cover handler. The door does not emit a distinct status code for "slug-shaped but unknown"; the response is whatever the cover handler returns for any other non-slug path. This is deliberate: the cover handler's response shape is what a prober must see for every miss, otherwise the door advertises its own existence as a redirector.

### Cover page fingerprinting

The cover handler's response is designed to look like a run-of-the-mill static page rather than like the output of a bespoke binary. Three properties matter.

First, the handler does not emit any header that identifies the software. No `Server: gateway-door`, no `X-Powered-By`, no `X-Request-Id` that leaks per-request state. The only headers on a cover response are those the operator configured under `headers:` plus the standard `Content-Type`, `Content-Length`, and `Date`.

Second, the `passthrough_404` cover kind returns `HTTP/1.1 404 Not Found` with `Server: nginx` and an empty body. This is the same shape an unconfigured default nginx install returns when no `server_name` matches. A scanner who probes a door with `passthrough_404` cover cannot distinguish it from a stock nginx at the response level; they would need to correlate with external metadata (TLS cert, timing, DNS footprint) to know the difference.

Third, the cover body is served byte-identically across requests. Two clients asking for `/` get the same response (modulo `Date`). No cookies, no per-client content, no query-string echo into the HTML. A prober who requests `/` five times from two different IPs cannot tell anything about per-visitor state.

Operators who host a door on a provider known to terminate TLS themselves should verify that the provider's TLS layer does not inject headers (some CDNs add `CF-Ray` or similar). Such headers leak the CDN's presence and may leak fingerprint bits an unfronted door would not. The door's own response does not emit these; the mitigation is a CDN choice, not a binary choice.

### Door log discipline

A door's access log is off by default in P2 on purpose. An access log on a machine that sees probing traffic accumulates high-entropy state (IPs, paths, timings) that is valuable to an attacker who roots the machine later. Doors keep state deliberately thin: the cover asset, the current slug list, the mirror snapshot, and a handful of Prometheus counters. Everything else (chosen mirror per redirect, per-IP frequencies, matched slug) is either DEBUG-level (off in production) or not computed at all.

Operators who need per-slug request counts use the hub-side metrics at `gateway_door_redirects_total{door, slug}`. This counter is aggregated and contains no per-request identifiers.

### Slug generation and storage

Slug strings are 32-character base32 random strings generated by the hub's crypto/rand. Each slug is stored in the hub's runtime config for the owning door and is included in the door's config-stream delivery. Slugs are not secrets in the same sense as mTLS keys (they appear in user-facing URLs by design), but they are sensitive: a leaked slug lets a prober send redirects through a door they otherwise know nothing about.

The hub's admin API returns slug strings in cleartext on `GET /v1/doors/<id>/slugs`; this endpoint is admin-only behind mTLS. The hub does not write slugs to log lines. The door does not log slugs except at DEBUG level for troubleshooting. A slug that is suspected to have leaked is rotated via `POST /v1/doors/<id>/slugs/rotate`, which keeps the old slug live for a grace window so that users who already had the URL do not immediately break.

### Per-install randomness for everything identifying

The installer generates fresh randomness for:

- `node_id` (unique per edge).
- Admin slug and two tokens (32 chars each).
- `node-secret` (32 bytes hex).
- WireGuard private key (25519).
- mTLS CA key (hub only, 4096-bit RSA).
- mTLS client key (per edge, 2048-bit ECDSA P-256).
- `metrics-salt` (32 bytes).

No value is derived from the domain name, hostname, or any other property of the machine. Reinstalling generates new identifiers; there is no stable-across-reinstall identifier other than what the operator chooses to preserve.

### systemd hardening

Every unit runs under an unprivileged `gateway` user with these hardening directives:

```
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
```

The proxy gets `AmbientCapabilities=CAP_NET_BIND_SERVICE` for ports 80 and 443 and nothing else. The torpool and hub get no capabilities beyond the default.

## What is not protected

### Network-level observer on both ends

An adversary who controls both the client network and the edge's uplink can correlate traffic by size, timing, or IP. Tor does not defend against global traffic analysis, and neither does the gateway. If this is your threat model, the gateway is not sufficient; consider Tor-to-Tor (both client and backend on hidden services).

### Metadata on the wire from client to edge

Client IP is visible to the edge. TLS SNI (the public hostname) is visible on the wire before TLS negotiation. `User-Agent`, cookies, and other HTTP headers are visible to the edge after TLS terminates. The gateway can strip headers with `proxy_headers.strip_upstream` before forwarding, but it cannot hide them from the edge itself.

If you need client-side anonymity, the client should use Tor (connect from a `.onion` or from a Tor exit to your public edge). The gateway does not hide clients; it hides backends.

### Backend responses that embed identifying content

If a backend serves HTML with absolute URLs pointing at the `.onion` or with cookies bound to the backend's domain, the content sanitizer does not rewrite them. It strips tags (`script`, `iframe`, etc.) and attributes (`onclick`, etc.), it does not rewrite URLs. Rewriting is complex, error-prone, and out of scope for P1. Operators must ensure backends do not leak identifying URLs; cookies should use `Domain=.your-domain.example` scope if they need to work across mirrors.

### Correlation via operator error

If an operator reuses a public domain across reinstalls, the tenant host stays the same and metrics labels hash identically across installs. If an operator reuses the same TLS account key across edges, the ACME account correlates them. If an operator logs the admin URL in a shell history file, that file leaks. These are policy problems, not code problems, and the gateway cannot prevent them.

The installer warns about a small set of common mistakes (shared domain across edges, weak admin bind address) but does not audit operator practices.

### Hub compromise

If the hub is rooted, everything is lost. The hub holds the CA key, the tenant list, every edge's allocated IP, and the salt used for hashing metrics and abuse IPs. There is no split-trust model in P1; the hub is fully trusted. Hardening the hub (no public internet reach, minimal userland, audited SSH access, offline backups) is the operator's responsibility.

### Side-channel vulnerabilities in dependencies

Go's crypto library, the Ristretto cache, BoltDB, the YAML parser, and the gRPC stack used in `https_tunnel` all have their own CVE history. The gateway does not defend against side channels in these dependencies beyond staying on current releases. Subscribe to the Go security list and watch this repo's advisories tag.

## Recommended hardening

### Network level

Put the hub on a private VPC or an offline-only machine behind a jump host. Edges should be the only entry point from the public internet. If you must expose the hub's admin port (for `https_tunnel` or `socks5_tls`), restrict the source IP to your edges' public IPs via firewall rules; do not rely on mTLS alone as the first line of defense.

Sample nftables on the hub (wireguard transport):

```
table inet gateway {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif lo accept
    iif wg0 tcp dport 9080 accept
    udp dport 51820 accept
    tcp dport 22 accept
    # drop everything else
  }
}
```

On edges, allow 80, 443, the transport port (51820 UDP for wireguard), and SSH. Drop everything else including ICMP except echo reply if you need remote debugging.

### Kernel sysctls

On the hub and on edges, set:

```
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.conf.all.accept_source_route=0
net.ipv6.conf.all.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
kernel.randomize_va_space=2
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
```

These are common hardening settings; they do not interact with the gateway specifically. Put them in `/etc/sysctl.d/99-gateway.conf`.

### fail2ban on edges

The gateway's internal rate limiter handles per-IP rate limits, but it does not ban persistent abusers at the kernel level. Install fail2ban with a jail that reads the edge's access log and blocks IPs that trigger repeated 429 responses or repeated 404s on blocked paths.

Jail example (`/etc/fail2ban/jail.d/gateway.conf`):

```
[gateway-flood]
enabled = true
filter  = gateway-flood
logpath = /var/log/gateway/proxy.log
maxretry = 30
findtime = 60
bantime = 3600
backend = auto
```

With a matching filter in `/etc/fail2ban/filter.d/gateway-flood.conf` matching log lines with HTTP 429 or 403. This is belt-and-braces; the application-level limit is always the first line of defense.

### Tor data directory on a chroot or tmpfs

The Tor instances' data directories live under `/var/lib/gateway/tor/`. They contain circuit state, onion descriptor caches, and client auth files (stealth keys). Consider putting them on a tmpfs for ephemerality:

```
# /etc/fstab
tmpfs /var/lib/gateway/tor tmpfs defaults,size=512M,mode=0700,uid=gateway,gid=gateway 0 0
```

This wipes the directory on every reboot. The downside is slightly longer bootstrap time on restart because Tor has no cached descriptors. For OPSEC-sensitive deployments this is the recommended tradeoff; for high-uptime low-risk deployments keep the on-disk directory.

### Offline backup of the hub CA

The hub CA key (`/etc/gateway/hub-ca.key`) is the root of trust. Losing it means reissuing every edge cert and redoing every registration. Copy it to an offline medium at install time and physically secure that medium. Do not store it in any cloud backup system that is not explicitly encrypted-at-rest with keys you control.

### Rotate the admin URL on suspicion

If you suspect the admin URL has leaked, regenerate the slug and tokens:

```bash
sudo bash deploy/install/step-06-admin.sh --regenerate
sudo systemctl restart gateway-proxy
```

The installer writes the new values into `/etc/gateway/config.yaml` and prints them once. Restart the proxy to pick them up. Old admin URL immediately stops matching (constant-time mismatch on the new slug).

### Minimize edge userland

Edges should not host any other service. No web server, no SSH from the internet (use a bastion), no mail relay. The smaller the userland, the fewer vulnerabilities that could be used to pivot. If the edge is on a VPS provider, use the smallest image that can run `gateway-proxy`.

### Audit the `gateway` user's shell

The `gateway` user should have `nologin` shell:

```
sudo usermod -s /usr/sbin/nologin gateway
```

Running `sudo -u gateway -i` should fail. No one logs in as `gateway`. All file access happens through the unit files.

## Known gaps

Several items are acknowledged gaps in P1:

- The content sanitizer does not rewrite URLs. Backends that leak their own `.onion` in response bodies will have that leak pass through. Planned for partial mitigation in P3.
- The admin gate handler does not exist yet (P3). The path returns 501 but is otherwise fully shaped, so once P3 lands the handler, OPSEC properties are already in place.
- No audit log on the admin API. Every admin action is logged, but there is no tamper-resistant audit log (append-only, signed). Planned for P3.
- No rate limit on the admin API itself. Running the admin API on a private network is the substitute until P3.
- Federation between hubs is not planned. Operators running multiple hubs maintain separate tenant lists and separate edges per hub.

Each gap has a corresponding issue label in the tracker; watch them if you deploy with an adversary model that demands any of the listed protections.
