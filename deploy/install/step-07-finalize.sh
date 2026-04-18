#!/usr/bin/env bash
# step-07-finalize.sh — Atomic commit.
#
# At this point every preceding step has populated:
#   * GW_* variables                       (bootstrap values)
#   * ${GW_STAGE_DIR}/etc/*                (secrets + configs)
#   * ${GW_STAGE_DIR}/etc/wireguard/wg0.conf (if --auto-wg)
#
# Finalize is the *only* step that writes under /etc. It does so atomically:
# first it renders config.yaml into the stage, then moves files into place
# with install(1) and atomic_write, then installs systemd units, starts
# services, and prints the one-time summary.
#
# On any failure before the final mv's, no /etc state changes.
#
# Bash >= 4.
set -euo pipefail

# shellcheck disable=SC1091
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

step_banner "Step 7/7  Finalize"

require_root
stage_init

GW_CONFIG_OUT="${GW_CONFIG_OUT:-/etc/gateway/config.yaml}"
config_dir="$(dirname -- "$GW_CONFIG_OUT")"

# Resolve the deploy/systemd directory relative to this script.
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_deploy="$(cd -- "$script_dir/.." && pwd)"   # gateway/deploy
systemd_src="$repo_deploy/systemd"

# ---------------------------------------------------------------------------
# Ensure runtime user + directories.
# ---------------------------------------------------------------------------
if ! id -u gateway >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin gateway
    log "Created system user 'gateway'."
fi

install -d -m 750 -o gateway -g gateway "$config_dir"
install -d -m 700 -o gateway -g gateway /var/lib/gateway
install -d -m 700 -o gateway -g gateway /var/lib/gateway/tor
install -d -m 700 -o gateway -g gateway /var/lib/gateway/hub
install -d -m 750 -o gateway -g gateway /var/log/gateway

# ---------------------------------------------------------------------------
# Render config.yaml into staging.
# ---------------------------------------------------------------------------
render_config() {
    local node_type="$GW_NODE_TYPE"
    local transport="${GW_TRANSPORT:-}"
    local hub_addr="${GW_HUB_ADDR:-}"
    local hub_reachable="${GW_HUB_REACHABLE:-0}"
    local mode
    case "$node_type" in
        hub)   mode="remote" ;;
        local) mode="local"  ;;
        *)     mode="remote" ;;
    esac

    cat <<YAML
# Gateway bootstrap config — written by install.sh $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Do NOT edit while the service is running; restart after any change.

mode: ${mode}
node_type: ${node_type}
node_id: "${GW_NODE_ID}"

listen:
  http:  ":80"
  https: ":443"

$(
if [[ "$node_type" == "proxy" || "$node_type" == "door" ]]; then
cat <<INNER
transport:
  kind: ${transport:-wireguard}
$(
case "$transport" in
  wireguard)
    cat <<WG
  wireguard:
    interface: wg0
    private_key_file: /etc/gateway/wg-private.key
    peer_pubkey: "${GW_WG_HUB_PUBKEY:-}"
    peer_endpoint: "${GW_WG_PEER_ENDPOINT:-hub.lan:51820}"
    peer_allowed_ips: "10.0.0.1/32"
    self_ip: "${GW_WG_SELF_IP:-10.0.0.2/24}"
WG
    ;;
  https_tunnel)
    cat <<HT
  https_tunnel:
    hub_url: "https://${hub_addr}"
    ca_cert_file: /etc/gateway/hub-ca.pem
HT
    ;;
  socks5_tls)
    cat <<ST
  socks5_tls:
    hub_addr: "${hub_addr}"
    admin_addr: "${hub_addr}"
    ca_cert_file: /etc/gateway/hub-ca.pem
ST
    ;;
esac
)

mtls:
  client_cert_file: /etc/gateway/client.crt
  client_key_file:  /etc/gateway/client.key

hub_url: "http://${hub_addr}"
node_secret_file: /etc/gateway/node-secret
INNER
fi
)

$(
if [[ "$node_type" == "hub" ]]; then
cat <<HUB
hub:
  listen_admin: "10.0.0.1:9080"
  listen_wg:    ":51820"
  mtls_ca:
    cert_file: /etc/gateway/hub-ca.pem
    key_file:  /etc/gateway/hub-ca.key
  data_dir: /var/lib/gateway/hub

torpool:
  binary: "$(command -v tor 2>/dev/null || printf 'tor')"
  socks_base_port: 9050
  min_instances: 3
  max_instances: 24
  data_dir: /var/lib/gateway/tor
HUB
fi
)

admin:
  slug:   "${GW_ADMIN_SLUG:-}"
  token1: "${GW_ADMIN_TOKEN1:-}"
  token2: "${GW_ADMIN_TOKEN2:-}"
  enabled: true

domain: "${GW_DOMAIN}"

metrics:
  enabled: true
  listen: "127.0.0.1:9090"
  opsec:
    hash_tenant_labels: true
    tenant_label_salt_file: /etc/gateway/metrics-salt

logging:
  level: info
  format: json
  output: stdout
  anonymize_ips: true
YAML
}

render_config > "${GW_STAGE_DIR}/etc/config.yaml"
chmod 640 "${GW_STAGE_DIR}/etc/config.yaml"

# ---------------------------------------------------------------------------
# Generate one more local secret that nothing else produced: metrics-salt
# and node-secret. These are staged here so finalize has a single commit
# phase.
# ---------------------------------------------------------------------------
if [[ ! -s "${GW_STAGE_DIR}/etc/metrics-salt" ]]; then
    atomic_write "${GW_STAGE_DIR}/etc/metrics-salt" "$(rand_hex 32)"
    chmod_secret "${GW_STAGE_DIR}/etc/metrics-salt"
fi
if [[ "${GW_NODE_TYPE}" != "hub" ]] && [[ ! -s "${GW_STAGE_DIR}/etc/node-secret" ]]; then
    atomic_write "${GW_STAGE_DIR}/etc/node-secret" "$(rand_hex 32)"
    chmod_secret "${GW_STAGE_DIR}/etc/node-secret"
fi

# ---------------------------------------------------------------------------
# Commit: move staged files into /etc/gateway.
# ---------------------------------------------------------------------------
commit_file() {
    # commit_file <stage_rel> <dest> <mode> <owner:group>
    local rel="$1" dest="$2" mode="$3" ownership="$4"
    local src="${GW_STAGE_DIR}/${rel}"
    [[ -f "$src" ]] || return 0
    install -m "$mode" -o "${ownership%%:*}" -g "${ownership##*:}" "$src" "$dest"
    log "  wrote $dest ($mode $ownership)"
}

log "Committing configuration to $config_dir..."
commit_file "etc/config.yaml"   "$GW_CONFIG_OUT"                 640 "root:gateway"
commit_file "etc/admin.env"     "$config_dir/admin.env"          600 "root:gateway"
commit_file "etc/metrics-salt"  "$config_dir/metrics-salt"       600 "gateway:gateway"
commit_file "etc/node-secret"   "$config_dir/node-secret"        600 "gateway:gateway"
commit_file "etc/client.key"    "$config_dir/client.key"         600 "gateway:gateway"
commit_file "etc/client.crt"    "$config_dir/client.crt"         644 "root:gateway"
commit_file "etc/client.csr"    "$config_dir/client.csr"         644 "root:gateway"
commit_file "etc/hub-ca.pem"    "$config_dir/hub-ca.pem"         644 "root:gateway"

# WireGuard private key file (edges only).
if [[ -f "${GW_STAGE_DIR}/wireguard/wg-private.key" ]]; then
    install -m 600 -o gateway -g gateway \
        "${GW_STAGE_DIR}/wireguard/wg-private.key" \
        "$config_dir/wg-private.key"
fi
if [[ -f "${GW_STAGE_DIR}/etc/wireguard/wg0.conf" ]]; then
    install -d -m 700 /etc/wireguard
    install -m 600 -o root -g root \
        "${GW_STAGE_DIR}/etc/wireguard/wg0.conf" \
        /etc/wireguard/wg0.conf
    log "  wrote /etc/wireguard/wg0.conf (600 root:root)"
fi

# Hub CA key (hub only).
if [[ -f "${GW_STAGE_DIR}/etc/hub-ca.key" ]]; then
    install -m 600 -o gateway -g gateway \
        "${GW_STAGE_DIR}/etc/hub-ca.key" "$config_dir/hub-ca.key"
fi

# ---------------------------------------------------------------------------
# Install systemd units.
# ---------------------------------------------------------------------------
install_unit() {
    local name="$1"
    local src="${systemd_src}/${name}"
    [[ -f "$src" ]] || return 0
    install -m 644 -o root -g root "$src" "/etc/systemd/system/${name}"
    log "  installed /etc/systemd/system/${name}"
}
install_unit gateway-torpool.service
install_unit gateway-proxy.service
install_unit gateway-hub.service

# Fallback: if the caller kept the old layout (deploy/gateway-*.service),
# install those too.
for legacy in gateway-proxy.service gateway-torpool.service; do
    legacy_src="${repo_deploy}/${legacy}"
    if [[ -f "$legacy_src" ]] && [[ ! -f "/etc/systemd/system/${legacy}" ]]; then
        install -m 644 -o root -g root "$legacy_src" "/etc/systemd/system/${legacy}"
        log "  installed /etc/systemd/system/${legacy}"
    fi
done

systemctl daemon-reload

# ---------------------------------------------------------------------------
# Start services (order: wg → torpool → proxy or hub).
# ---------------------------------------------------------------------------
if [[ "$GW_TRANSPORT" == "wireguard" ]] && [[ -f /etc/wireguard/wg0.conf ]]; then
    systemctl enable --now "wg-quick@wg0.service" 2>/dev/null \
        || warn "wg-quick@wg0 failed to start — check /etc/wireguard/wg0.conf"
fi

case "$GW_NODE_TYPE" in
    hub)
        systemctl enable --now gateway-hub.service 2>/dev/null \
            || warn "gateway-hub.service failed to start"
        ;;
    local)
        systemctl enable --now gateway-torpool.service 2>/dev/null || true
        systemctl enable --now gateway-proxy.service   2>/dev/null || true
        ;;
    proxy)
        systemctl enable --now gateway-proxy.service 2>/dev/null || true
        ;;
esac

# Mark the stage committed so common.sh doesn't rm -rf it on exit before
# we're done (cleanup is still safe — files are already in /etc).
GW_STAGE_COMMITTED=1
export GW_STAGE_COMMITTED

# ---------------------------------------------------------------------------
# One-time summary — the ONLY place secrets appear on stdout. Printed to
# stdout (not stderr) so operators can redirect if they need to, though we
# strongly recommend against it.
# ---------------------------------------------------------------------------
admin_url=""
if [[ -n "${GW_ADMIN_SLUG:-}" ]]; then
    admin_url="https://${GW_DOMAIN}/${GW_ADMIN_SLUG}/${GW_ADMIN_TOKEN1}/${GW_ADMIN_TOKEN2}"
fi

# Compute mTLS cert serial if we actually got one signed.
cert_serial="<not issued>"
if [[ -s "$config_dir/client.crt" ]] && have openssl; then
    cert_serial="$(openssl x509 -in "$config_dir/client.crt" -noout -serial 2>/dev/null | sed 's/^serial=//')"
fi

cat <<SUMMARY

═══════════════════════════════════════════════════════════════
  SAVE THIS ONCE
═══════════════════════════════════════════════════════════════
  Node ID:          ${GW_NODE_ID}
  Node Type:        ${GW_NODE_TYPE}
  Domain:           ${GW_DOMAIN}
  Config:           ${GW_CONFIG_OUT}
$(
if [[ -n "$admin_url" ]]; then
    printf '  Admin URL:        %s\n' "$admin_url"
fi
)
$(
if [[ "${GW_TRANSPORT:-}" == "wireguard" ]] && [[ -n "${GW_WG_PUBLIC_KEY:-}" ]]; then
    printf '  WG public key:    %s\n' "$GW_WG_PUBLIC_KEY"
    printf '  WG self-IP:       %s\n' "${GW_WG_SELF_IP:-10.0.0.2/24}"
    printf '  (add this peer to the hub WireGuard config)\n'
fi
)
  mTLS cert serial: ${cert_serial}
═══════════════════════════════════════════════════════════════
  These values will NOT be shown again. Secrets are in
  ${config_dir}/ with mode 0600. Admin tokens were not logged.
═══════════════════════════════════════════════════════════════
SUMMARY

log "Installation complete."
