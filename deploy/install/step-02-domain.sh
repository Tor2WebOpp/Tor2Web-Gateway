#!/usr/bin/env bash
# step-02-domain.sh — Public domain this node will serve.
#
# Outputs:
#   GW_DOMAIN
#
# Bash >= 4.
set -euo pipefail

# shellcheck disable=SC1091
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

step_banner "Step 2/7  Public domain"

if [[ -n "${GW_DOMAIN:-}" ]]; then
    if ! validate_domain "$GW_DOMAIN"; then
        die "invalid --domain: $GW_DOMAIN"
    fi
    log "Domain (from flag): $GW_DOMAIN"
else
    info "Enter the public hostname users will reach this node on."
    info "For a hub behind a private overlay, you can use the internal name."
    GW_DOMAIN="$(ask_free 'Public domain' '' validate_domain)"
    export GW_DOMAIN
fi

# Derive a short node ID unless already set. We use a stable-ish slug of the
# hostname + 4 bytes of entropy. node_id is NOT a secret — it just needs to
# be unique per install.
if [[ -z "${GW_NODE_ID:-}" ]]; then
    # First label of the domain, lowercased, non-alnum stripped.
    first_label="${GW_DOMAIN%%.*}"
    first_label="$(printf '%s' "$first_label" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9')"
    [[ -z "$first_label" ]] && first_label="node"
    # Truncate to 16 chars to leave room for the suffix.
    first_label="${first_label:0:16}"
    suffix="$(rand_hex 2)"   # 4 hex chars
    case "${GW_NODE_TYPE:-proxy}" in
        hub)   GW_NODE_ID="hub-${first_label}-${suffix}"   ;;
        local) GW_NODE_ID="local-${first_label}-${suffix}" ;;
        *)     GW_NODE_ID="edge-${first_label}-${suffix}"  ;;
    esac
    export GW_NODE_ID
fi

log "Step 2 complete: GW_DOMAIN=$GW_DOMAIN GW_NODE_ID=$GW_NODE_ID"
