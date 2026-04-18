# P1 Integration Test Harness

End-to-end tests for the P1 multi-tenant + remote-hub gateway build.

## What this exercises

| # | Test | Covers |
|---|---|---|
| 01 | `proxy-1 /healthz` routes via Tor to `backend-a` | tenant routing, Host header demux |
| 02 | `proxy-1 /wp-admin` → 404 (blocklist rule) | `blocklist_regex` feature, tenant override |
| 03 | `proxy-2 /wp-admin` → 200 (no rule on tenant B) | per-tenant isolation |
| 04 | `/big-static.css` second hit is faster | `static_cache` feature |
| 05 | `PUT /v1/tenants/...` propagates to edge in <2s | hub admin API + SSE config stream |
| 06 | `DELETE /v1/tenants/...` → proxy returns 421 | tenant lifecycle, `Misdirected Request` semantics |
| 07 | Admin gate `/{slug}/{t1}/{t2}` → 501, otherwise 404 | P1 carve-out stub, constant-time leak prevention |

## Prerequisites

- **Docker 24+**
- **Docker Compose v2** (`docker compose`, not the deprecated `docker-compose`)
- ~2 GB free RAM
- No ports are published to the host; the harness is fully self-contained.

## Running

From the repository root (one level above `gateway/`):

```bash
cd gateway
docker compose -f docker-compose.p1-integration.yml up \
    --build \
    --abort-on-container-exit \
    --exit-code-from driver
```

The exit code equals the number of failed tests. All green = 0.

### Tearing down

```bash
docker compose -f docker-compose.p1-integration.yml down -v --remove-orphans
```

The `-v` removes the named volumes so the next run starts clean.

## Services

| Service | Port (internal) | Role |
|---|---|---|
| `tor-1`, `tor-2`, `tor-3` | 9050 | Tor client + hidden-service mapping |
| `backend-a` | 8080 | Plain-HTTP echo backend for tenant A |
| `backend-b` | 8080 | Plain-HTTP echo backend for tenant B |
| `hub` | 9080 | `gateway-hub` admin + SSE stream |
| `proxy-1` | 443 | `gateway-proxy` for tenant A |
| `proxy-2` | 443 | `gateway-proxy` for tenant B |
| `driver` | — | Go test runner; exits with `#fails` |

All services share a single bridge network (`p1net`). Docker's embedded DNS resolves service names, so the driver reaches the hub at `https://hub:9080` and the proxies at `https://proxy-1`, `https://proxy-2`.

## Config files

`config/` holds the bootstrap YAML for each process:

- `hub.yaml` — hub bootstrap (admin listener, CA paths, data dir)
- `proxy-1.yaml` — edge proxy for tenant A (mode=remote, hub=hub:9080)
- `proxy-2.yaml` — edge proxy for tenant B

`runtime/` holds the hub-owned runtime state that is mounted into the hub container:

- `globals.yaml` — feature defaults
- `tenants/example-a.yaml` — tenant A (backend = deterministic v3 onion mapped to `backend-a`)
- `tenants/example-b.yaml` — tenant B (backend = deterministic v3 onion mapped to `backend-b`)

Note: the onion addresses in the tenant files are real v3 format (56-char base32 + checksum), generated from deterministic all-0x01 / all-0x02 keys. They pass `ValidateOnionV3`. Inside the harness, Tor's HiddenService rules map those addresses to the Docker backends so the hub's SOCKS5 dialler succeeds without a public Tor network.

## Troubleshooting

### "Services never became ready" from the driver

Open a second terminal and inspect:

```bash
docker compose -f docker-compose.p1-integration.yml logs hub
docker compose -f docker-compose.p1-integration.yml logs proxy-1
```

Common causes:

- Hub config rejected by `config.Load` — YAML syntax or missing required field.
- Tor healthcheck flapping — `osminogin/tor-simple` can take 30–60s to bootstrap.
- Clock skew between Docker and host that breaks TLS — run `docker restart`.

### "hub PUT returned 401: mTLS required"

The integration build of the hub is expected to disable mTLS on the admin listener when `GATEWAY_INTEGRATION=1`. If you see 401, the hub binary was built without the `-tags=integration` flag. Check `Dockerfile.hub`.

### Tests 05/06 (tenant propagation) fail with timeout

The proxy's SSE subscriber may take longer than 2s to reconnect on first boot. Re-run; if consistently failing, bump the timeouts in `driver/main.go` and open an issue — the P1 SLA is 2s but the first boot is a cold-start edge case.

### Tests 04 (cache) flaky on Windows

Ristretto cache admission is async. On slow hosts the second hit may not beat the first. The driver permits a generous (2x or <100ms) window; if it still fails, run on Linux or increase the payload in `backend/main.go`.

## CI integration

Add to GitHub Actions / GitLab CI:

```yaml
- name: P1 integration tests
  working-directory: gateway
  run: |
    docker compose -f docker-compose.p1-integration.yml up \
      --build \
      --abort-on-container-exit \
      --exit-code-from driver
```

`--exit-code-from driver` propagates the driver's exit code to the runner, so the pipeline fails iff any test failed.

## Files

```
tests/integration/
├── Dockerfile.backend         # tiny echo server
├── Dockerfile.driver          # test runner
├── Dockerfile.hub             # gateway-hub image
├── Dockerfile.proxy           # gateway-proxy image
├── README.md                  # this file
├── backend/main.go            # echo server source
├── driver/main.go             # test matrix source
├── config/
│   ├── hub.yaml
│   ├── proxy-1.yaml
│   └── proxy-2.yaml
└── runtime/
    ├── globals.yaml
    └── tenants/
        ├── example-a.yaml
        └── example-b.yaml
```

## Known limitations (P1)

- **mTLS is disabled on the hub's admin listener** inside the harness so the driver can PUT/DELETE tenants without a client cert. Production hubs enforce mTLS; unit tests in `internal/hub/` cover the auth path.
- **WireGuard is not actually started** — the `transport.kind: wireguard` in the proxy configs is honoured by the schema but the integration build tag short-circuits to plain TCP dialling of the hub service. Real WG integration lives in OS-level install tests, not docker.
- **Tor bootstrap is faked**. The `osminogin/tor-simple` containers run a Tor process but no real circuits are built. The hub's SOCKS5 dial is redirected to the Docker backend service via the HiddenService mapping. Real Tor end-to-end lives in staging, not in CI.
- **The gateway-hub binary may not yet exist** on some branches — `Dockerfile.hub` falls back to `gateway-proxy` as a placeholder so the scaffolding works during parallel development. When `cmd/gateway-hub/main.go` lands, the fallback drops out automatically.
