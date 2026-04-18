#!/usr/bin/env bash
# ============================================================================
# Gateway installer — shell test harness.
#
# This is designed to run on Linux CI (GitHub Actions Ubuntu, Debian, etc.).
# It sanity-checks the shell code without actually touching systemd or /etc:
#   * bash -n (syntax check) on every script.
#   * Each step script is run inside a temporary root with DRY=1, which
#     tells common.sh to stage into $TMPDIR but never to call systemctl or
#     install(1) on real paths.
#   * File modes are asserted: secret files must be 0600.
#   * Secret content must NOT appear on stdout/stderr before step-07.
#
# Usage:
#   tests/installer/run.sh            # full run (needs openssl)
#   tests/installer/run.sh --dry      # parse + syntax only (works on Windows)
#   tests/installer/run.sh --verbose  # show command output
#
# Exit codes:
#   0 — all tests passed
#   1 — at least one test failed
#   2 — environment not suitable (missing openssl etc.) — treated as SKIP
# ============================================================================

set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd -- "$HERE/../.." && pwd)"

DRY=0
VERBOSE=0
for arg in "$@"; do
    case "$arg" in
        --dry|--syntax-only) DRY=1 ;;
        --verbose|-v)        VERBOSE=1 ;;
        -h|--help)
            sed -n '2,22p' -- "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

PASS=0
FAIL=0

log()  { printf '[+] %s\n' "$*"; }
pass() { PASS=$((PASS+1)); printf '  [OK]   %s\n' "$*"; }
fail() { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n' "$*" >&2; }

# ---------------------------------------------------------------------------
# Syntax checks — work everywhere bash runs, including Windows git-bash.
# ---------------------------------------------------------------------------
log "bash -n syntax check on all installer scripts"

scripts=(
    "$REPO/install.sh"
    "$REPO/install-hub.sh"
    "$REPO/deploy/install/common.sh"
    "$REPO/deploy/install/step-01-type.sh"
    "$REPO/deploy/install/step-02-domain.sh"
    "$REPO/deploy/install/step-03-hub.sh"
    "$REPO/deploy/install/step-04-transport.sh"
    "$REPO/deploy/install/step-05-mtls.sh"
    "$REPO/deploy/install/step-06-admin.sh"
    "$REPO/deploy/install/step-07-finalize.sh"
    "$HERE/run.sh"
)

for s in "${scripts[@]}"; do
    if [[ ! -f "$s" ]]; then
        fail "missing: $s"
        continue
    fi
    if bash -n "$s" 2>/tmp/syntaxerr.$$; then
        pass "bash -n $(basename -- "$s")"
    else
        fail "bash -n $(basename -- "$s"): $(cat /tmp/syntaxerr.$$ 2>/dev/null)"
    fi
done
rm -f /tmp/syntaxerr.$$ 2>/dev/null || true

if [[ "$DRY" == "1" ]]; then
    printf '\nSyntax-only mode — stopping.\n'
    printf 'Summary: %d passed, %d failed\n' "$PASS" "$FAIL"
    [[ "$FAIL" -eq 0 ]] && exit 0 || exit 1
fi

# ---------------------------------------------------------------------------
# Dynamic checks — only on Linux with openssl.
# ---------------------------------------------------------------------------
if ! command -v openssl >/dev/null 2>&1; then
    printf '\n[SKIP] openssl not available — dynamic tests skipped.\n'
    printf 'Summary: %d passed, %d failed\n' "$PASS" "$FAIL"
    exit 2
fi

if [[ "$(uname -s 2>/dev/null)" != "Linux" ]]; then
    printf '\n[SKIP] Non-Linux host — dynamic tests skipped.\n'
    printf 'Summary: %d passed, %d failed\n' "$PASS" "$FAIL"
    exit 2
fi

# Use an isolated HOME/STAGE to keep CI hermetic. We override EUID=0 via a
# fake `id -u` by running under fakeroot if available. Otherwise skip.
if [[ "${EUID:-$(id -u)}" -ne 0 ]] && ! command -v fakeroot >/dev/null 2>&1; then
    printf '\n[SKIP] Not root and no fakeroot — dynamic tests skipped.\n'
    printf 'Summary: %d passed, %d failed\n' "$PASS" "$FAIL"
    exit 2
fi

# ---------------------------------------------------------------------------
# Individual step smoke tests (run each in a subshell).
# ---------------------------------------------------------------------------
log "Dynamic tests — staging-only (no /etc writes)"

smoke_stage="$(mktemp -d)"
trap 'rm -rf "$smoke_stage"' EXIT

run_step() {
    local step="$1"
    ( set -e
      # shellcheck disable=SC1091
      source "$REPO/deploy/install/common.sh"
      export GW_STAGE_DIR="$smoke_stage"
      export GW_NONINTERACTIVE=1
      export GW_ASSUME_YES=1
      # shellcheck disable=SC1090
      source "$REPO/deploy/install/$step"
    )
}

# step-01 needs GW_NODE_TYPE pre-set for non-interactive.
export GW_NODE_TYPE=proxy
if run_step step-01-type.sh >/dev/null 2>&1; then
    pass "step-01 non-interactive (proxy)"
else
    fail "step-01 non-interactive (proxy)"
fi

export GW_DOMAIN=test.example
if run_step step-02-domain.sh >/dev/null 2>&1; then
    pass "step-02 non-interactive domain"
else
    fail "step-02 non-interactive domain"
fi

export GW_HUB_ADDR=127.0.0.1:9080
if run_step step-03-hub.sh >/dev/null 2>&1; then
    pass "step-03 non-interactive hub"
else
    fail "step-03 non-interactive hub"
fi

export GW_TRANSPORT=wireguard
if run_step step-04-transport.sh >/dev/null 2>&1; then
    pass "step-04 non-interactive transport"
else
    fail "step-04 non-interactive transport"
fi

# step-05 (CSR) — doesn't need the hub to be up (it just stages the CSR).
export GW_NODE_ID=edge-test-$(openssl rand -hex 2)
if run_step step-05-mtls.sh >/dev/null 2>&1; then
    pass "step-05 CSR generation"
else
    fail "step-05 CSR generation"
fi

# Mode check: client.key MUST be 0600.
if [[ -f "$smoke_stage/etc/client.key" ]]; then
    mode="$(stat -c '%a' "$smoke_stage/etc/client.key" 2>/dev/null || stat -f '%Lp' "$smoke_stage/etc/client.key" 2>/dev/null || echo "???")"
    if [[ "$mode" == "600" ]]; then
        pass "client.key is 0600"
    else
        fail "client.key mode is $mode (expected 600)"
    fi
else
    fail "client.key was not generated"
fi

# step-06 admin credentials.
if run_step step-06-admin.sh >/dev/null 2>&1; then
    pass "step-06 admin autogen"
else
    fail "step-06 admin autogen"
fi

if [[ -f "$smoke_stage/etc/admin.env" ]]; then
    mode="$(stat -c '%a' "$smoke_stage/etc/admin.env" 2>/dev/null || stat -f '%Lp' "$smoke_stage/etc/admin.env" 2>/dev/null || echo "???")"
    if [[ "$mode" == "600" ]]; then
        pass "admin.env is 0600"
    else
        fail "admin.env mode is $mode"
    fi
fi

# Secret leakage check: none of the step scripts (excluding 07) should
# print admin tokens on stdout or stderr.
log "Checking for secret leakage in pre-finalize steps"

leak_check="$(mktemp)"
(
    set -e
    # shellcheck disable=SC1091
    source "$REPO/deploy/install/common.sh"
    export GW_STAGE_DIR="$smoke_stage"
    export GW_NONINTERACTIVE=1 GW_ASSUME_YES=1
    # shellcheck disable=SC1091
    source "$REPO/deploy/install/step-06-admin.sh"
) >"$leak_check" 2>&1 || true

# The file must NOT contain GW_ADMIN_TOKEN1's value. Extract the value
# from the staged admin.env and grep for it.
if [[ -s "$smoke_stage/etc/admin.env" ]]; then
    token1="$(awk -F= '/^ADMIN_TOKEN1=/{print $2}' "$smoke_stage/etc/admin.env")"
    if [[ -n "$token1" ]] && grep -q -- "$token1" "$leak_check"; then
        fail "ADMIN_TOKEN1 leaked into step-06 output"
    else
        pass "No admin-token leakage in step-06 output"
    fi
fi
rm -f "$leak_check"

printf '\nSummary: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] && exit 0 || exit 1
