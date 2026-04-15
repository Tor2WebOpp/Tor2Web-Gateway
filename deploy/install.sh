#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Require root
if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

echo "==> Creating gateway system user..."
if ! id -u gateway &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin gateway
    echo "    Created user: gateway"
else
    echo "    User already exists: gateway"
fi

echo "==> Creating directories..."
install -d -m 750 -o gateway -g gateway \
    /opt/gateway \
    /etc/gateway \
    /var/lib/gateway/tor \
    /var/log/gateway \
    /var/run/gateway

echo "==> Copying binaries..."
for bin in gateway-proxy gateway-torpool; do
    src="${REPO_ROOT}/bin/${bin}"
    if [[ ! -f "${src}" ]]; then
        echo "ERROR: Binary not found: ${src}" >&2
        echo "       Run 'make build' first." >&2
        exit 1
    fi
    install -m 755 -o root -g root "${src}" "/opt/gateway/${bin}"
    echo "    Installed: /opt/gateway/${bin}"
done

echo "==> Copying config..."
if [[ ! -f /etc/gateway/config.yaml ]]; then
    if [[ -f "${REPO_ROOT}/config.example.yaml" ]]; then
        install -m 600 -o root -g gateway "${REPO_ROOT}/config.example.yaml" /etc/gateway/config.yaml
        echo "    Installed example config: /etc/gateway/config.yaml"
        echo "    IMPORTANT: Edit /etc/gateway/config.yaml before starting services."
    else
        echo "    WARNING: No config.example.yaml found; /etc/gateway/config.yaml not created."
        echo "             Create /etc/gateway/config.yaml manually before starting services."
    fi
else
    echo "    Config already exists, skipping: /etc/gateway/config.yaml"
fi

echo "==> Setting permissions..."
chmod 600 /etc/gateway/config.yaml 2>/dev/null || true
chmod 755 /opt/gateway/gateway-proxy /opt/gateway/gateway-torpool
chmod 750 /opt/gateway /etc/gateway /var/lib/gateway /var/log/gateway /var/run/gateway

echo "==> Installing systemd units..."
install -m 644 -o root -g root "${SCRIPT_DIR}/gateway-torpool.service" /etc/systemd/system/gateway-torpool.service
install -m 644 -o root -g root "${SCRIPT_DIR}/gateway-proxy.service"   /etc/systemd/system/gateway-proxy.service
systemctl daemon-reload
echo "    Installed: gateway-torpool.service, gateway-proxy.service"

echo "==> Configuring iptables..."
# Allow established/related connections (must be first)
iptables -C INPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \
    || iptables -I INPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -C OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \
    || iptables -I OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow inbound HTTP / HTTPS
iptables -C INPUT -p tcp --dport 80  -j ACCEPT 2>/dev/null \
    || iptables -A INPUT -p tcp --dport 80  -j ACCEPT
iptables -C INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null \
    || iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow outbound to localhost SOCKS port range (9050-9149 default)
iptables -C OUTPUT -o lo -p tcp --dport 9050:9149 -j ACCEPT 2>/dev/null \
    || iptables -A OUTPUT -o lo -p tcp --dport 9050:9149 -j ACCEPT

# Drop other outbound traffic that is not established (optional strict policy)
# NOTE: This rule is intentionally last so earlier ACCEPT rules take priority.
iptables -C OUTPUT -m state --state NEW -j DROP 2>/dev/null \
    || iptables -A OUTPUT -m state --state NEW -j DROP

echo "    iptables rules applied."

echo "==> Enabling and starting services..."
systemctl enable --now gateway-torpool.service
systemctl enable --now gateway-proxy.service

echo ""
echo "==> Status:"
systemctl status gateway-torpool.service --no-pager || true
echo ""
systemctl status gateway-proxy.service --no-pager || true

echo ""
echo "==> Installation complete."
