#!/usr/bin/env bash
# ============================================================================
# Gateway — Phased Interactive Installer
# ============================================================================
#
# This is the top-level driver. It sources deploy/install/common.sh and then
# runs deploy/install/step-*.sh in order. Each step is self-contained and
# can be re-run independently for debugging.
#
# Usage (interactive):
#   sudo ./install.sh
#
# Usage (non-interactive, e.g. Ansible):
#   sudo ./install.sh \
#       --type=proxy \
#       --domain=mirror-7.example \
#       --hub=10.0.0.1:9080 \
#       --transport=wireguard \
#       --auto-wg \
#       --admin-autogen \
#       --yes
#
# Flags:
#   --type=<hub|proxy|local|door>  Node type.
#   --domain=<fqdn>                Public hostname the node serves.
#   --hub=<host[:port]>            Hub address (ignored for hub/local).
#   --transport=<wireguard|https_tunnel|socks5_tls>
#   --auto-wg                      Auto-provision WireGuard (requires transport=wireguard).
#   --admin-autogen                Auto-generate admin slug + tokens (always on by default).
#   --config-out=<path>            Where to write config.yaml (default /etc/gateway/config.yaml).
#   --cover-kind=<static_file|static_html|passthrough_404>
#                                  (door only) Cover asset kind. Default static_file.
#   --cover-path=<path>            (door only) Path to the cover asset to copy.
#   --yes                          Assume yes for all confirmations.
#   -h | --help                    Print this help.
#
# Required bash: >= 4.0
# POSIX-compat: not strict — bash features (arrays, =~) are used.
#
# On error: nothing is written to /etc until step-07 runs successfully. The
# staging directory is rm -rf'd on exit.
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="$SCRIPT_DIR/deploy/install"

if [[ ! -d "$INSTALL_DIR" ]]; then
    printf '[ERROR] installer sub-scripts not found at %s\n' "$INSTALL_DIR" >&2
    exit 1
fi

# shellcheck disable=SC1091
source "$INSTALL_DIR/common.sh"

# ---------------------------------------------------------------------------
# Flag parsing.
# ---------------------------------------------------------------------------
GW_NODE_TYPE="${GW_NODE_TYPE:-}"
GW_DOMAIN="${GW_DOMAIN:-}"
GW_HUB_ADDR="${GW_HUB_ADDR:-}"
GW_TRANSPORT="${GW_TRANSPORT:-}"
GW_AUTO_WG="${GW_AUTO_WG:-0}"
GW_ADMIN_AUTOGEN="${GW_ADMIN_AUTOGEN:-1}"
GW_CONFIG_OUT="${GW_CONFIG_OUT:-/etc/gateway/config.yaml}"
GW_ASSUME_YES="${GW_ASSUME_YES:-0}"
GW_NONINTERACTIVE="${GW_NONINTERACTIVE:-0}"
# Door-only fields (empty otherwise).
GW_COVER_KIND="${GW_COVER_KIND:-}"
GW_COVER_PATH="${GW_COVER_PATH:-}"

usage() {
    sed -n '2,32p' -- "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

for arg in "$@"; do
    case "$arg" in
        --type=*)        GW_NODE_TYPE="${arg#*=}" ;;
        --domain=*)      GW_DOMAIN="${arg#*=}" ;;
        --hub=*)         GW_HUB_ADDR="${arg#*=}" ;;
        --transport=*)   GW_TRANSPORT="${arg#*=}" ;;
        --auto-wg)       GW_AUTO_WG=1 ;;
        --admin-autogen) GW_ADMIN_AUTOGEN=1 ;;
        --config-out=*)  GW_CONFIG_OUT="${arg#*=}" ;;
        --cover-kind=*)  GW_COVER_KIND="${arg#*=}" ;;
        --cover-path=*)  GW_COVER_PATH="${arg#*=}" ;;
        --yes|-y)        GW_ASSUME_YES=1 ;;
        -h|--help)       usage 0 ;;
        *) die "unknown argument: $arg (use --help for usage)" ;;
    esac
done
export GW_NODE_TYPE GW_DOMAIN GW_HUB_ADDR GW_TRANSPORT GW_AUTO_WG \
       GW_ADMIN_AUTOGEN GW_CONFIG_OUT GW_ASSUME_YES GW_NONINTERACTIVE \
       GW_COVER_KIND GW_COVER_PATH

# Decide if we're non-interactive: all required fields were supplied.
if [[ -n "$GW_NODE_TYPE" && -n "$GW_DOMAIN" ]] \
   && { [[ "$GW_NODE_TYPE" == "hub" || "$GW_NODE_TYPE" == "local" ]] \
        || { [[ -n "$GW_HUB_ADDR" ]] && [[ -n "$GW_TRANSPORT" ]]; }; } \
   && [[ "$GW_ASSUME_YES" == "1" ]]; then
    GW_NONINTERACTIVE=1
    export GW_NONINTERACTIVE
    log "Non-interactive mode."
else
    log "Interactive mode — flags will be used as defaults where provided."
fi

# ---------------------------------------------------------------------------
# Banner — no project-identifying codename (OPSEC).
# ---------------------------------------------------------------------------
cat >&2 <<BANNER
${GW_C_BOLD}╔════════════════════════════════════════════════════════╗
║           Gateway Installer                            ║
╚════════════════════════════════════════════════════════╝${GW_C_RESET}
BANNER

require_root
stage_init

# ---------------------------------------------------------------------------
# Run each step in order. On error the EXIT trap cleans the staging dir.
# ---------------------------------------------------------------------------
run_step() {
    local script="$1"
    local path="$INSTALL_DIR/$script"
    [[ -f "$path" ]] || die "missing step script: $path"
    # Source the step so it inherits / mutates the GW_* environment.
    # shellcheck disable=SC1090
    source "$path"
}

# Pass a hint to step-01 so it can warn if 'hub' is selected via install.sh
# rather than install-hub.sh.
export GW_ENTRYPOINT="install.sh"

run_step step-01-type.sh
run_step step-02-domain.sh
run_step step-03-hub.sh
run_step step-04-transport.sh
# Door-only: cover asset + initial slug.
if [[ "$GW_NODE_TYPE" == "door" ]]; then
    run_step step-04b-cover.sh
fi
run_step step-05-mtls.sh
run_step step-06-admin.sh

# Final confirmation before committing.
if [[ "$GW_NONINTERACTIVE" != "1" ]]; then
    step_banner "Summary"
    dump_state_nonsecret
    confirm "Commit configuration and start services?" || die "aborted by user"
fi

run_step step-07-finalize.sh
