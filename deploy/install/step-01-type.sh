#!/usr/bin/env bash
# step-01-type.sh — Node-type selection.
#
# Outputs:
#   GW_NODE_TYPE  = hub | proxy | local | door
#
# Bash >= 4.
set -euo pipefail

# shellcheck disable=SC1091
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

step_banner "Step 1/7  Node type"

if [[ -n "${GW_NODE_TYPE:-}" ]] && validate_node_type "$GW_NODE_TYPE"; then
    log "Node type (from flag): $GW_NODE_TYPE"
else
    choice="$(ask_choice 'Select node type:' \
        'hub     — central controller (tor pool, tenant registry, CA)' \
        'proxy   — edge mirror (connects to a hub)' \
        'local   — single-box all-in-one (backwards compatible)' \
        'door    — slug redirector with cover page (P2)')"
    case "$choice" in
        hub*)   GW_NODE_TYPE=hub   ;;
        proxy*) GW_NODE_TYPE=proxy ;;
        local*) GW_NODE_TYPE=local ;;
        door*)  GW_NODE_TYPE=door  ;;
        *) die "unexpected node type selection: $choice" ;;
    esac
    export GW_NODE_TYPE
fi

case "$GW_NODE_TYPE" in
    door)
        log "Selected: gateway-door (P2)"
        info "Door mode selected — a slug redirector that fronts healthy mirrors."
        info "After the base flow, step-04b will ask about the cover asset."
        ;;
    hub)
        info "Hub mode selected."
        if [[ "${GW_ENTRYPOINT:-}" != "install-hub.sh" ]]; then
            warn "Hub mode is usually installed via install-hub.sh, which"
            warn "also provisions the mTLS CA. You can continue here — the"
            warn "finalize step will still write a hub config."
        fi
        ;;
    proxy) info "Proxy (edge) mode selected." ;;
    local) info "Local all-in-one mode selected." ;;
esac

log "Step 1 complete: GW_NODE_TYPE=$GW_NODE_TYPE"
