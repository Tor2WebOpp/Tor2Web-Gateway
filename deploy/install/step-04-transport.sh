#!/usr/bin/env bash
# step-04-transport.sh — Transport selection + optional wg bootstrap.
#
# Outputs:
#   GW_TRANSPORT       = wireguard | https_tunnel | socks5_tls
#   GW_WG_PRIVATE_KEY  (only when transport=wireguard, staged, not committed)
#   GW_WG_PUBLIC_KEY   (printed to user in step-07)
#   GW_WG_SELF_IP      (e.g. 10.0.0.42/24)
#
# Bash >= 4.
set -euo pipefail

# shellcheck disable=SC1091
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

step_banner "Step 4/7  Transport"

case "${GW_NODE_TYPE:-}" in
    hub|local)
        log "Skipping transport step (node type: $GW_NODE_TYPE)"
        GW_TRANSPORT="${GW_TRANSPORT:-}"
        export GW_TRANSPORT
        exit 0
        ;;
esac

if [[ -n "${GW_TRANSPORT:-}" ]]; then
    if ! validate_transport "$GW_TRANSPORT"; then
        die "invalid --transport: $GW_TRANSPORT"
    fi
    log "Transport (from flag): $GW_TRANSPORT"
else
    choice="$(ask_choice 'Select transport to the hub:' \
        'wireguard     (default, recommended: UDP overlay)' \
        'https_tunnel  (WebSocket-over-TLS, works anywhere)' \
        'socks5_tls    (raw SOCKS5 over TLS, last resort)')"
    case "$choice" in
        wireguard*)    GW_TRANSPORT=wireguard    ;;
        https_tunnel*) GW_TRANSPORT=https_tunnel ;;
        socks5_tls*)   GW_TRANSPORT=socks5_tls   ;;
        *) die "unexpected transport: $choice" ;;
    esac
    export GW_TRANSPORT
fi

stage_init

# ---------------------------------------------------------------------------
# WireGuard auto-provision.
# ---------------------------------------------------------------------------
if [[ "$GW_TRANSPORT" == "wireguard" ]] && [[ "${GW_AUTO_WG:-0}" == "1" ]]; then
    info "Auto-provisioning WireGuard client config."

    if ! have wg; then
        info "Installing wireguard-tools..."
        pkg_install wireguard-tools
    fi
    have wg || die "wg is not available after install attempt"

    # Generate keys in a safe, 0700 temp dir — never in the staging directory
    # root where they could leak if the user ls's it.
    keydir="${GW_STAGE_DIR}/wireguard"
    mkdir -p "$keydir"
    chmod 700 "$keydir"

    GW_WG_PRIVATE_KEY="$(wg genkey)"
    GW_WG_PUBLIC_KEY="$(printf '%s' "$GW_WG_PRIVATE_KEY" | wg pubkey)"
    export GW_WG_PRIVATE_KEY GW_WG_PUBLIC_KEY

    # Decide a self-IP. If caller didn't pick one, default to 10.0.0.2/24
    # (hub is .1). The hub admin is expected to register the public key and
    # assign the final address; this is a sensible placeholder.
    GW_WG_SELF_IP="${GW_WG_SELF_IP:-10.0.0.2/24}"
    export GW_WG_SELF_IP

    # Private key file (staged).
    atomic_write "${keydir}/wg-private.key" "$GW_WG_PRIVATE_KEY"
    chmod_secret "${keydir}/wg-private.key"

    # wg-quick conf for wg0 — the hub's public key is filled in step-07 once
    # the hub hands us its key. For now the peer section is a placeholder.
    wg_conf=$(cat <<WGEOF
# Written by gateway install.sh — edit with care.
[Interface]
PrivateKey = ${GW_WG_PRIVATE_KEY}
Address = ${GW_WG_SELF_IP}

# Peer block is filled in by finalize once the hub pubkey is known.
# [Peer]
# PublicKey = <hub-wg-pubkey>
# Endpoint  = <hub-endpoint>:51820
# AllowedIPs = 10.0.0.1/32
# PersistentKeepalive = 25
WGEOF
)
    stage_write "etc/wireguard/wg0.conf" "$wg_conf"
    chmod_secret "${GW_STAGE_DIR}/etc/wireguard/wg0.conf"

    log "WireGuard keys generated and staged (not yet committed)."
elif [[ "$GW_TRANSPORT" == "wireguard" ]]; then
    info "wireguard selected but --auto-wg not set."
    info "You'll need to configure /etc/wireguard/wg0.conf manually before"
    info "starting services in step-07."
fi

log "Step 4 complete: GW_TRANSPORT=$GW_TRANSPORT"
