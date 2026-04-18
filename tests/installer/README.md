# Gateway installer test harness

Shell-based smoke tests for `install.sh`, `install-hub.sh`, and the phased
`deploy/install/step-*.sh` scripts.

## Running

```bash
# Full run (Linux, needs openssl; runs as root or under fakeroot)
tests/installer/run.sh

# Syntax-only — works on Windows git-bash too
tests/installer/run.sh --dry
```

## What it verifies

| Check | Where |
|---|---|
| `bash -n` parses every installer script | all platforms |
| Each step can be sourced non-interactively (`GW_*` env pre-set) | Linux |
| `client.key`, `admin.env`, `node-secret`, `metrics-salt` are mode `0600` | Linux |
| No admin token appears on stdout/stderr before `step-07-finalize.sh` | Linux |
| `validate_domain` accepts / rejects the right inputs | Linux |

## What it does NOT do

* No real `systemctl` calls — the harness stops before finalize. A full
  end-to-end test belongs in a docker-compose integration suite (see
  `docker-compose.p1-integration.yml` once it lands in P1).
* No network calls. step-03's reachability probe and step-05's CSR
  submission are exercised only via fixtures (not wired up yet; TODO).
* No tests for the WireGuard key-generation path; that requires
  `wireguard-tools` in the CI image.

## Environment

On non-Linux hosts (Windows, macOS) the harness runs in `--dry` mode
automatically — it returns 0 if syntax checks pass and exit code 2 ("skip")
if it cannot run the dynamic portion.

CI should invoke it as:

```bash
tests/installer/run.sh --dry     # runs in every job
tests/installer/run.sh           # only in linux-root job
```

## Dependencies

* bash >= 4.0
* openssl (only for the dynamic portion)
* fakeroot (fallback for non-root Linux environments)
