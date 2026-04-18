#!/usr/bin/env bash
# common.sh — shared helpers for the phased Gateway installer.
#
# Sourced (not executed) by install.sh, install-hub.sh, and every
# deploy/install/step-*.sh. Must work under bash >= 4 (arrays, `declare`),
# strict-mode aware, and safe to re-source.
#
# Conventions:
#   * All exported installer state lives in variables prefixed with GW_.
#   * Never write to /etc until step-07 (finalize). Step scripts populate
#     a stage directory given by GW_STAGE_DIR (caller sets this once).
#   * Secrets are never echoed outside of step-07's "SAVE THIS ONCE" block.
#   * No analytics, no telemetry, no outbound calls from this file.
#
# Minimum bash: 4.0 (associative arrays used by callers).

# Guard against double-sourcing.
if [[ -n "${_GW_COMMON_SOURCED:-}" ]]; then
    return 0 2>/dev/null || exit 0
fi
_GW_COMMON_SOURCED=1

set -euo pipefail

# ---------------------------------------------------------------------------
# Colors — only when stdout is a TTY AND TERM says it supports colors.
# ---------------------------------------------------------------------------
if [[ -t 1 ]] && [[ "${TERM:-dumb}" != "dumb" ]] && command -v tput >/dev/null 2>&1 && [[ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]]; then
    GW_C_RED=$'\033[0;31m'
    GW_C_GREEN=$'\033[0;32m'
    GW_C_YELLOW=$'\033[1;33m'
    GW_C_CYAN=$'\033[0;36m'
    GW_C_BOLD=$'\033[1m'
    GW_C_RESET=$'\033[0m'
else
    GW_C_RED=''
    GW_C_GREEN=''
    GW_C_YELLOW=''
    GW_C_CYAN=''
    GW_C_BOLD=''
    GW_C_RESET=''
fi

# ---------------------------------------------------------------------------
# Logging helpers. Everything goes to stderr so stdout is reserved for
# structured output (secrets printed only in finalize step).
# ---------------------------------------------------------------------------
log()  { printf '%s[+]%s %s\n' "$GW_C_GREEN"  "$GW_C_RESET" "$*" >&2; }
warn() { printf '%s[!]%s %s\n' "$GW_C_YELLOW" "$GW_C_RESET" "$*" >&2; }
info() { printf '%s[i]%s %s\n' "$GW_C_CYAN"   "$GW_C_RESET" "$*" >&2; }
die()  { printf '%s[ERROR]%s %s\n' "$GW_C_RED" "$GW_C_RESET" "$*" >&2; exit 1; }
step_banner() {
    local title="$1"
    printf '\n%s=== %s ===%s\n' "$GW_C_CYAN" "$title" "$GW_C_RESET" >&2
}

# have <cmd> — returns 0 if command is on PATH.
have() { command -v "$1" >/dev/null 2>&1; }

# rand_hex <bytes> — prints N bytes of hex randomness via openssl.
rand_hex() {
    local n="${1:-32}"
    have openssl || die "openssl is required for random generation"
    openssl rand -hex "$n"
}

# tmp_dir — echoes a freshly-created mode-0700 temp directory.
# Registers cleanup via GW_CLEANUP_DIRS (trap wired up below).
declare -a GW_CLEANUP_DIRS=()
tmp_dir() {
    local d
    d="$(mktemp -d 2>/dev/null || mktemp -d -t gw-install)"
    chmod 700 "$d"
    GW_CLEANUP_DIRS+=("$d")
    printf '%s\n' "$d"
}

_gw_cleanup_tmp() {
    local d
    # Only clean up staging tmp dirs that are NOT the final committed one.
    for d in "${GW_CLEANUP_DIRS[@]:-}"; do
        [[ -n "$d" && -d "$d" && "${GW_STAGE_COMMITTED:-0}" != "1" ]] || continue
        rm -rf -- "$d" 2>/dev/null || true
    done
}
trap _gw_cleanup_tmp EXIT

# atomic_write <path> <content> — writes file via mktemp + mv.
# The parent directory must already exist. Sets 0600 by default; callers
# can chmod after if they need something looser.
atomic_write() {
    local path="$1"
    local content="$2"
    local dir tmp
    dir="$(dirname -- "$path")"
    [[ -d "$dir" ]] || die "atomic_write: parent directory does not exist: $dir"
    tmp="$(mktemp "${dir}/.$(basename -- "$path").XXXXXX")"
    printf '%s' "$content" > "$tmp"
    chmod 600 "$tmp"
    mv -f -- "$tmp" "$path"
}

# chmod_secret <path> — set 0600 permissions, fail loudly if it doesn't stick.
chmod_secret() {
    local path="$1"
    [[ -e "$path" ]] || die "chmod_secret: $path does not exist"
    chmod 600 -- "$path"
}

# ---------------------------------------------------------------------------
# Input helpers — interactive mode. Read from /dev/tty so they work even when
# the installer is piped. In non-interactive (--yes) mode, callers must set
# the backing GW_* variable before calling.
# ---------------------------------------------------------------------------

# confirm <msg> — y/N prompt. Returns 0 on yes, 1 on no / empty.
confirm() {
    local msg="$1" answer
    if [[ "${GW_NONINTERACTIVE:-0}" == "1" ]]; then
        # In non-interactive mode, assume yes IF the user passed --yes.
        [[ "${GW_ASSUME_YES:-0}" == "1" ]] && return 0
        die "confirmation required but --yes not given: $msg"
    fi
    printf '%s[?]%s %s [y/N]: ' "$GW_C_YELLOW" "$GW_C_RESET" "$msg" > /dev/tty
    read -r answer < /dev/tty || answer=""
    [[ "$answer" =~ ^[Yy]$ ]]
}

# ask_choice <prompt> <choice1> <choice2> ... — echoes the chosen value.
# Prints a numbered menu to /dev/tty and validates selection.
ask_choice() {
    local prompt="$1"
    shift
    local -a choices=("$@")
    local n="${#choices[@]}" i answer
    (( n > 0 )) || die "ask_choice: no choices given"

    {
        printf '%s%s%s\n' "$GW_C_BOLD" "$prompt" "$GW_C_RESET"
        for i in "${!choices[@]}"; do
            printf '  %s[%d]%s %s\n' "$GW_C_CYAN" "$((i+1))" "$GW_C_RESET" "${choices[i]}"
        done
    } > /dev/tty

    while :; do
        printf '  Choice [1-%d]: ' "$n" > /dev/tty
        read -r answer < /dev/tty || die "no input"
        if [[ "$answer" =~ ^[0-9]+$ ]] && (( answer >= 1 && answer <= n )); then
            printf '%s\n' "${choices[$((answer-1))]}"
            return 0
        fi
        printf '  %sInvalid choice.%s\n' "$GW_C_YELLOW" "$GW_C_RESET" > /dev/tty
    done
}

# ask_free <prompt> <default> [validator_fn] — echoes the final value.
# validator_fn, if given, is called with the candidate value; it must
# return 0 to accept, non-zero to re-prompt.
ask_free() {
    local prompt="$1"
    local default_val="${2:-}"
    local validator_fn="${3:-}"
    local answer

    while :; do
        if [[ -n "$default_val" ]]; then
            printf '%s[?]%s %s [%s]: ' "$GW_C_YELLOW" "$GW_C_RESET" "$prompt" "$default_val" > /dev/tty
        else
            printf '%s[?]%s %s: ' "$GW_C_YELLOW" "$GW_C_RESET" "$prompt" > /dev/tty
        fi
        read -r answer < /dev/tty || die "no input"
        answer="${answer:-$default_val}"

        if [[ -z "$answer" ]]; then
            printf '  %sValue cannot be empty.%s\n' "$GW_C_YELLOW" "$GW_C_RESET" > /dev/tty
            continue
        fi

        if [[ -n "$validator_fn" ]]; then
            if "$validator_fn" "$answer"; then
                printf '%s\n' "$answer"
                return 0
            else
                printf '  %sInvalid value.%s\n' "$GW_C_YELLOW" "$GW_C_RESET" > /dev/tty
                continue
            fi
        fi
        printf '%s\n' "$answer"
        return 0
    done
}

# ---------------------------------------------------------------------------
# Validators — return 0 if valid, non-zero otherwise. No side effects.
# ---------------------------------------------------------------------------
validate_domain() {
    local d="$1"
    # RFC-1123-ish: labels 1-63 chars, alnum + hyphen, no leading/trailing
    # hyphen, total length <= 253.
    [[ ${#d} -le 253 ]] || return 1
    [[ "$d" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]] || return 1
    return 0
}

validate_hub_addr() {
    # Accepts host:port, ip:port, ipv4, plain host. Port optional.
    local a="$1"
    [[ -n "$a" ]] || return 1
    # Strip trailing :port if present.
    local host port
    if [[ "$a" =~ ^(.+):([0-9]+)$ ]]; then
        host="${BASH_REMATCH[1]}"
        port="${BASH_REMATCH[2]}"
        (( port > 0 && port < 65536 )) || return 1
    else
        host="$a"
    fi
    # Allow IPv4, bare hostname, or FQDN.
    if [[ "$host" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
        return 0
    fi
    validate_domain "$host"
}

validate_node_type() {
    case "$1" in
        hub|proxy|door|local) return 0 ;;
        *) return 1 ;;
    esac
}

validate_transport() {
    case "$1" in
        wireguard|https_tunnel|socks5_tls) return 0 ;;
        *) return 1 ;;
    esac
}

# ---------------------------------------------------------------------------
# Package manager detection / install.
# ---------------------------------------------------------------------------
pkg_install() {
    local pkg="$1"
    if have apt-get; then
        DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$pkg" >/dev/null 2>&1 \
            || die "apt-get install failed: $pkg"
    elif have dnf; then
        dnf install -y "$pkg" >/dev/null 2>&1 || die "dnf install failed: $pkg"
    elif have yum; then
        yum install -y "$pkg" >/dev/null 2>&1 || die "yum install failed: $pkg"
    else
        die "no supported package manager found to install: $pkg"
    fi
}

# ---------------------------------------------------------------------------
# Staging helpers. GW_STAGE_DIR is the tmp directory that receives all
# files during steps 1-6; step-07 promotes it atomically into /etc.
# ---------------------------------------------------------------------------
stage_init() {
    if [[ -z "${GW_STAGE_DIR:-}" ]]; then
        GW_STAGE_DIR="$(tmp_dir)"
        export GW_STAGE_DIR
        mkdir -p "$GW_STAGE_DIR/etc" "$GW_STAGE_DIR/wireguard"
    fi
}

stage_write() {
    # stage_write <relpath> <content>
    stage_init
    local rel="$1" content="$2"
    local full="${GW_STAGE_DIR}/${rel}"
    mkdir -p "$(dirname -- "$full")"
    atomic_write "$full" "$content"
}

# ---------------------------------------------------------------------------
# Root check — bails unless EUID==0. Callers that want to be flexible can
# guard this.
# ---------------------------------------------------------------------------
require_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        die "this script must be run as root (use sudo)"
    fi
}

# Print GW_* state (excluding secret-ish keys) — useful for step summaries.
dump_state_nonsecret() {
    local v
    for v in GW_NODE_TYPE GW_DOMAIN GW_HUB_ADDR GW_TRANSPORT GW_AUTO_WG GW_ADMIN_AUTOGEN GW_CONFIG_OUT GW_NODE_ID; do
        printf '  %-20s = %s\n' "$v" "${!v:-<unset>}" >&2
    done
}
