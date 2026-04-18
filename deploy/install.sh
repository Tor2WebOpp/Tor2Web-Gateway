#!/usr/bin/env bash
# ============================================
# Gateway — Install Script
# Safe, idempotent, won't break running services
# ============================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
step() { echo -e "\n${GREEN}=== $1 ===${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ============================================
# 0. Pre-flight checks (BEFORE touching anything)
# ============================================
step "Pre-flight checks"

[[ "${EUID}" -ne 0 ]] && err "This script must be run as root (sudo ./install.sh)"

# Check binaries exist
for bin in gateway-proxy gateway-torpool; do
    [[ ! -f "${SCRIPT_DIR}/${bin}" ]] && err "Binary not found: ${SCRIPT_DIR}/${bin}\n       Run 'make build' on your local machine first."
    log "Found: bin/${bin}"
done

# Check Tor is installed
if ! command -v tor &>/dev/null; then
    warn "Tor is not installed. Installing..."
    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq tor > /dev/null 2>&1
        # Disable default tor service — torpool manages its own instances
        systemctl stop tor 2>/dev/null || true
        systemctl disable tor 2>/dev/null || true
        log "Tor installed and default service disabled"
    elif command -v dnf &>/dev/null; then
        dnf install -y tor > /dev/null 2>&1
        systemctl stop tor 2>/dev/null || true
        systemctl disable tor 2>/dev/null || true
        log "Tor installed and default service disabled"
    else
        err "Cannot install Tor automatically. Install manually: apt install tor"
    fi
else
    log "Tor found: $(tor --version | head -1)"
fi

TOR_PATH="$(command -v tor)"
log "Tor binary: ${TOR_PATH}"

# ============================================
# 1. Create system user (safe — skips if exists)
# ============================================
step "System user"

if ! id -u gateway &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin gateway
    log "Created user: gateway"
else
    log "User already exists: gateway"
fi

# ============================================
# 2. Create directories (safe — idempotent)
# ============================================
step "Directories"

install -d -m 750 -o gateway -g gateway /opt/gateway
install -d -m 750 -o gateway -g gateway /etc/gateway
install -d -m 700 -o gateway -g gateway /var/lib/gateway
install -d -m 700 -o gateway -g gateway /var/lib/gateway/tor
install -d -m 750 -o gateway -g gateway /var/log/gateway
# /run/gateway is managed by systemd RuntimeDirectory — don't create manually

log "Directories ready"

# ============================================
# 3. Stop services GRACEFULLY before replacing binaries
# (only if they're currently running)
# ============================================
step "Stopping existing services (if running)"

PROXY_WAS_RUNNING=false
TORPOOL_WAS_RUNNING=false

if systemctl is-active --quiet gateway-proxy 2>/dev/null; then
    PROXY_WAS_RUNNING=true
    log "Stopping gateway-proxy..."
    systemctl stop gateway-proxy
fi

if systemctl is-active --quiet gateway-torpool 2>/dev/null; then
    TORPOOL_WAS_RUNNING=true
    log "Stopping gateway-torpool..."
    systemctl stop gateway-torpool
fi

if [[ "$PROXY_WAS_RUNNING" == "false" && "$TORPOOL_WAS_RUNNING" == "false" ]]; then
    log "No existing services running (fresh install)"
fi

# ============================================
# 4. Install binaries (only after services are stopped)
# ============================================
step "Installing binaries"

for bin in gateway-proxy gateway-torpool; do
    install -m 755 -o root -g root "${SCRIPT_DIR}/${bin}" "/opt/gateway/${bin}"
    log "Installed: /opt/gateway/${bin}"
done

# ============================================
# 5. Config file (NEVER overwrite existing config!)
# ============================================
step "Configuration"

CONFIG_READY=true
if [[ ! -f /etc/gateway/config.yaml ]]; then
    if [[ -f "${SCRIPT_DIR}/config.example.yaml" ]]; then
        install -m 640 -o root -g gateway "${SCRIPT_DIR}/config.example.yaml" /etc/gateway/config.yaml
        warn "Installed EXAMPLE config: /etc/gateway/config.yaml"
        warn ">>> YOU MUST EDIT THIS FILE BEFORE STARTING SERVICES <<<"
        warn ">>> At minimum: domain, proxy_secret, backends <<<"
        CONFIG_READY=false
    else
        err "No config.example.yaml found and no config exists on server"
    fi
else
    # Fix permissions on existing config (may have wrong perms from old install)
    chown root:gateway /etc/gateway/config.yaml
    chmod 640 /etc/gateway/config.yaml
    log "Config exists: /etc/gateway/config.yaml (permissions fixed to 640 root:gateway)"
fi

# ============================================
# 6. Update config to use real tor path
# ============================================
if grep -q 'binary:.*tor$\|binary:.*"/usr/bin/tor"' /etc/gateway/config.yaml 2>/dev/null; then
    sed -i "s|binary:.*|binary: \"${TOR_PATH}\"|" /etc/gateway/config.yaml
    log "Updated tor.binary in config to: ${TOR_PATH}"
fi

# ============================================
# 7. Install systemd units (safe — daemon-reload after)
# ============================================
step "Systemd units"

install -m 644 -o root -g root "${SCRIPT_DIR}/gateway-torpool.service" /etc/systemd/system/gateway-torpool.service
install -m 644 -o root -g root "${SCRIPT_DIR}/gateway-proxy.service"   /etc/systemd/system/gateway-proxy.service
systemctl daemon-reload
log "Units installed and daemon reloaded"

# ============================================
# 8. Firewall rules (idempotent — checks before adding)
# ============================================
step "Firewall (iptables)"

# Helper: add rule only if not already present
add_rule() {
    local chain="$1"; shift
    if ! iptables -C "$chain" "$@" 2>/dev/null; then
        iptables -A "$chain" "$@"
        log "  Added: iptables -A $chain $*"
    fi
}
add_rule_insert() {
    local chain="$1"; shift
    if ! iptables -C "$chain" "$@" 2>/dev/null; then
        iptables -I "$chain" "$@"
        log "  Added: iptables -I $chain $*"
    fi
}

# --- Loopback (MUST be first — everything local needs this) ---
add_rule_insert INPUT  -i lo -j ACCEPT
add_rule_insert OUTPUT -o lo -j ACCEPT

# --- Established/related (allow return traffic for all connections) ---
add_rule INPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT
add_rule OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# --- Inbound: HTTP/HTTPS from anywhere (Cloudflare) ---
add_rule INPUT -p tcp --dport 80  -j ACCEPT
add_rule INPUT -p tcp --dport 443 -j ACCEPT

# --- Outbound: Tor relay connections (torpool needs internet for bootstrap) ---
# Tor connects to directory authorities and relays on various ports.
# We allow ALL outbound TCP for the gateway user (who runs tor via torpool).
# This is safe because:
# - The gateway user only runs our binaries
# - gateway-proxy needs outbound for: ACME (Let's Encrypt), CF IP range fetch
# - gateway-torpool needs outbound for: Tor bootstrap to relay network
add_rule OUTPUT -m owner --uid-owner gateway -p tcp -j ACCEPT

# --- Outbound: DNS (needed for ACME, CF IP fetch) ---
add_rule OUTPUT -p udp --dport 53 -j ACCEPT
add_rule OUTPUT -p tcp --dport 53 -j ACCEPT

# NOTE: We intentionally do NOT add a blanket DROP rule.
# Reason: it breaks SSH, apt, system updates, NTP, etc.
# Use 'ufw' or a dedicated firewall script for full lockdown.
# Our security model: Cloudflare hides origin IP + gateway only listens on 80/443.

log "Firewall configured"

# ============================================
# 9. Enable services (but only START if config is ready)
# ============================================
step "Starting services"

systemctl enable gateway-torpool.service
systemctl enable gateway-proxy.service
log "Services enabled (will start on boot)"

if [[ "$CONFIG_READY" == "true" ]]; then
    log "Starting gateway-torpool..."
    systemctl start gateway-torpool.service

    # Wait for torpool to create the unix socket before starting proxy
    log "Waiting for torpool socket..."
    SOCKET_PATH=$(grep -oP 'socket:\s*"\K[^"]+' /etc/gateway/config.yaml 2>/dev/null || echo "/run/gateway/torpool.sock")
    for i in $(seq 1 30); do
        if [[ -S "${SOCKET_PATH}" ]]; then
            log "Socket ready: ${SOCKET_PATH}"
            break
        fi
        sleep 1
    done

    log "Starting gateway-proxy..."
    systemctl start gateway-proxy.service
    sleep 2
else
    warn "Services NOT started — config has placeholder values."
    warn "Edit /etc/gateway/config.yaml then run:"
    warn "  systemctl start gateway-torpool && sleep 10 && systemctl start gateway-proxy"
fi

# ============================================
# 10. Status report
# ============================================
step "Status"

echo ""
echo -e "  Tor binary:      ${GREEN}${TOR_PATH}${NC}"
echo -e "  Config:          ${GREEN}/etc/gateway/config.yaml${NC}"
echo -e "  Binaries:        ${GREEN}/opt/gateway/gateway-{proxy,torpool}${NC}"
echo -e "  Logs:            ${GREEN}/var/log/gateway/${NC}"
echo -e "  Tor data:        ${GREEN}/var/lib/gateway/tor/${NC}"
echo ""

if [[ "$CONFIG_READY" == "true" ]]; then
    echo -e "  gateway-torpool: $(systemctl is-active gateway-torpool 2>/dev/null || echo 'unknown')"
    echo -e "  gateway-proxy:   $(systemctl is-active gateway-proxy 2>/dev/null || echo 'unknown')"
else
    echo -e "  gateway-torpool: ${YELLOW}not started (config not ready)${NC}"
    echo -e "  gateway-proxy:   ${YELLOW}not started (config not ready)${NC}"
fi

echo ""
if [[ "$CONFIG_READY" == "false" ]]; then
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  NEXT STEP: Edit /etc/gateway/config.yaml           ║${NC}"
    echo -e "${YELLOW}║  Then: systemctl start gateway-torpool               ║${NC}"
    echo -e "${YELLOW}║  Wait 30s, then: systemctl start gateway-proxy       ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════╝${NC}"
fi

echo ""
log "Installation complete."
