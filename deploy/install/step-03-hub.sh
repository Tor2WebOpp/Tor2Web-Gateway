#!/usr/bin/env bash
# step-03-hub.sh — Hub address (skipped for hub/local).
#
# Outputs:
#   GW_HUB_ADDR     (host[:port] form the edge will talk to)
#   GW_HUB_REACHABLE (0 = unknown, 1 = reachable)
#
# Bash >= 4.
set -euo pipefail

# shellcheck disable=SC1091
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

step_banner "Step 3/7  Hub address"

case "${GW_NODE_TYPE:-}" in
    hub|local)
        log "Skipping hub address (node type: $GW_NODE_TYPE)"
        GW_HUB_ADDR=""
        export GW_HUB_ADDR
        exit 0
        ;;
esac

if [[ -n "${GW_HUB_ADDR:-}" ]]; then
    if ! validate_hub_addr "$GW_HUB_ADDR"; then
        die "invalid --hub: $GW_HUB_ADDR"
    fi
    log "Hub address (from flag): $GW_HUB_ADDR"
else
    info "The edge will talk to the hub over the chosen transport."
    info "For wireguard: usually an internal address like 10.0.0.1:9080"
    info "For https_tunnel: the public hub URL, e.g. hub.example:8443"
    GW_HUB_ADDR="$(ask_free 'Hub address (host[:port])' '' validate_hub_addr)"
    export GW_HUB_ADDR
fi

# Best-effort reachability probe. We don't hard-fail on this: in wireguard
# mode the hub address is often unreachable until wg comes up.
GW_HUB_REACHABLE=0
hub_host="${GW_HUB_ADDR%%:*}"
hub_port=""
if [[ "$GW_HUB_ADDR" == *:* ]]; then
    hub_port="${GW_HUB_ADDR##*:}"
fi

if have curl && [[ -n "$hub_port" ]]; then
    # Try an HTTP probe with a short timeout.
    if curl --silent --show-error --max-time 3 --output /dev/null \
        "http://${GW_HUB_ADDR}/v1/health" 2>/dev/null; then
        GW_HUB_REACHABLE=1
    fi
fi

if [[ "$GW_HUB_REACHABLE" == "0" ]] && have ping; then
    # Fall back to a plain ICMP probe. One packet, one-second timeout.
    if ping -c 1 -W 1 "$hub_host" >/dev/null 2>&1; then
        GW_HUB_REACHABLE=1
    fi
fi

if [[ "$GW_HUB_REACHABLE" == "1" ]]; then
    log "Hub at $GW_HUB_ADDR appears reachable."
else
    warn "Hub at $GW_HUB_ADDR is not reachable yet. That is normal for"
    warn "wireguard-based transports before the tunnel is up; step-07"
    warn "will bring the tunnel online."
fi

export GW_HUB_REACHABLE
log "Step 3 complete: GW_HUB_ADDR=$GW_HUB_ADDR GW_HUB_REACHABLE=$GW_HUB_REACHABLE"
