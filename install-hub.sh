#!/usr/bin/env bash
# ============================================================================
# Gateway — Hub Installer
# ============================================================================
#
# Convenience wrapper around install.sh with node_type preset to "hub".
# The hub:
#   * Does NOT submit a CSR (step-05 is skipped for hubs).
#   * Generates its own mTLS CA (root cert + key) in /etc/gateway/.
#   * Optionally generates a WireGuard server key pair for the overlay.
#   * Writes /etc/gateway/hub-ca.pem for edges to download.
#   * Installs deploy/systemd/gateway-hub.service.
#
# Usage:
#   sudo ./install-hub.sh [--domain=hub.example] [--yes]
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="$SCRIPT_DIR/deploy/install"

# shellcheck disable=SC1091
source "$INSTALL_DIR/common.sh"

GW_NODE_TYPE=hub
GW_DOMAIN="${GW_DOMAIN:-}"
GW_ASSUME_YES="${GW_ASSUME_YES:-0}"
GW_CONFIG_OUT="${GW_CONFIG_OUT:-/etc/gateway/config.yaml}"
GW_GENERATE_WG_SERVER="${GW_GENERATE_WG_SERVER:-0}"

usage() {
    sed -n '2,18p' -- "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

for arg in "$@"; do
    case "$arg" in
        --domain=*)     GW_DOMAIN="${arg#*=}" ;;
        --config-out=*) GW_CONFIG_OUT="${arg#*=}" ;;
        --wg-server)    GW_GENERATE_WG_SERVER=1 ;;
        --yes|-y)       GW_ASSUME_YES=1 ;;
        -h|--help)      usage 0 ;;
        *) die "unknown argument: $arg (use --help for usage)" ;;
    esac
done
export GW_NODE_TYPE GW_DOMAIN GW_ASSUME_YES GW_CONFIG_OUT GW_GENERATE_WG_SERVER

cat >&2 <<BANNER
${GW_C_BOLD}╔════════════════════════════════════════════════════════╗
║           Gateway Hub Installer                        ║
╚════════════════════════════════════════════════════════╝${GW_C_RESET}
BANNER

require_root
stage_init

# Non-interactive if --yes and --domain given.
if [[ -n "$GW_DOMAIN" ]] && [[ "$GW_ASSUME_YES" == "1" ]]; then
    GW_NONINTERACTIVE=1
    export GW_NONINTERACTIVE
fi

export GW_ENTRYPOINT="install-hub.sh"

# Step 1 is a no-op for us (type is preset) but we still source it so the
# exported variable is sanity-checked.
# shellcheck disable=SC1091
source "$INSTALL_DIR/step-01-type.sh"

# shellcheck disable=SC1091
source "$INSTALL_DIR/step-02-domain.sh"

# step-03 and step-04 short-circuit for hubs.
# shellcheck disable=SC1091
source "$INSTALL_DIR/step-03-hub.sh"
# shellcheck disable=SC1091
source "$INSTALL_DIR/step-04-transport.sh"

# ---------------------------------------------------------------------------
# Generate the hub's mTLS CA (ECDSA P-256, 10-year validity).
# This replaces step-05-mtls.sh (which is no-op for hubs).
# ---------------------------------------------------------------------------
step_banner "Hub mTLS CA generation"

have openssl || die "openssl is required to generate the CA"

ca_key="${GW_STAGE_DIR}/etc/hub-ca.key"
ca_pem="${GW_STAGE_DIR}/etc/hub-ca.pem"

mkdir -p "${GW_STAGE_DIR}/etc"

openssl ecparam -name prime256v1 -genkey -noout -out "$ca_key" 2>/dev/null \
    || die "CA key generation failed"
chmod_secret "$ca_key"

# Self-signed root certificate. The CN is a neutral label.
openssl req -x509 -new -nodes -key "$ca_key" -sha256 -days 3650 \
    -subj "/CN=gateway hub CA" -out "$ca_pem" 2>/dev/null \
    || die "CA self-signing failed"
chmod 644 "$ca_pem"

log "Generated self-signed ECDSA P-256 CA (10-year validity)."

# ---------------------------------------------------------------------------
# Optional: generate a WireGuard server key pair for the hub overlay.
# ---------------------------------------------------------------------------
if [[ "$GW_GENERATE_WG_SERVER" == "1" ]]; then
    if ! have wg; then
        info "Installing wireguard-tools..."
        pkg_install wireguard-tools
    fi
    hub_wg_priv="$(wg genkey)"
    hub_wg_pub="$(printf '%s' "$hub_wg_priv" | wg pubkey)"
    atomic_write "${GW_STAGE_DIR}/etc/wg-hub-private.key" "$hub_wg_priv"
    chmod_secret "${GW_STAGE_DIR}/etc/wg-hub-private.key"
    GW_WG_PUBLIC_KEY="$hub_wg_pub"
    export GW_WG_PUBLIC_KEY
    log "Generated hub WireGuard server keypair."
fi

# shellcheck disable=SC1091
source "$INSTALL_DIR/step-06-admin.sh"

if [[ "${GW_NONINTERACTIVE:-0}" != "1" ]]; then
    step_banner "Summary"
    dump_state_nonsecret
    confirm "Commit hub configuration and start services?" || die "aborted by user"
fi

# shellcheck disable=SC1091
source "$INSTALL_DIR/step-07-finalize.sh"

# Final extra hint for edges.
cat >&2 <<EDGEHELP

Hub is online. To enroll an edge:
  1. Copy the CA bundle to the edge:
       scp ${GW_CONFIG_OUT%/*}/hub-ca.pem edge-host:/etc/gateway/hub-ca.pem
  2. On the edge, run:
       sudo install.sh --type=proxy --domain=<edge.fqdn> \
           --hub=<this-hub-ip-or-fqdn>:9080 \
           --transport=wireguard --auto-wg --yes
EDGEHELP
