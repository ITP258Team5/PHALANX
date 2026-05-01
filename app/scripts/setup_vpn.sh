#!/usr/bin/env bash
set -euo pipefail

# ══════════════════════════════════════════════════════════════
# Phalanx VPN Setup — Tailscale Integration
#
# Adds encrypted remote access to Phalanx via Tailscale VPN.
# After setup, you can:
#   1. Access the dashboard from anywhere (not just your LAN)
#   2. Route your phone/laptop DNS through Phalanx on any network
#   3. Manage the Pi remotely via SSH over Tailscale
#
# Prerequisites:
#   - A free Tailscale account (https://tailscale.com)
#   - Internet access on the Pi
# ══════════════════════════════════════════════════════════════

echo ""
echo "========================================"
echo "  Phalanx VPN Setup (Tailscale)"
echo "========================================"
echo ""

if [[ $EUID -ne 0 ]]; then
    echo "Error: Run as root (sudo bash $0)"
    exit 1
fi

PI_IP=$(hostname -I | awk '{print $1}')

# ── 1. Install Tailscale ──
echo "[1/4] Installing Tailscale..."

if command -v tailscale &>/dev/null; then
    echo "       Tailscale already installed"
else
    curl -fsSL https://tailscale.com/install.sh | sh
    echo "       ✅ Tailscale installed"
fi

# ── 2. Enable IP forwarding (required for exit node / DNS routing) ──
echo "[2/4] Enabling IP forwarding..."

# IPv4
if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi

# IPv6
if ! grep -q "^net.ipv6.conf.all.forwarding=1" /etc/sysctl.conf 2>/dev/null; then
    echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
fi

sysctl -p > /dev/null 2>&1
echo "       ✅ IP forwarding enabled"

# ── 3. Start Tailscale with DNS and exit node capabilities ──
echo "[3/4] Starting Tailscale..."
echo ""
echo "  A browser link will appear below. Open it to authenticate"
echo "  with your Tailscale account."
echo ""

tailscale up \
    --advertise-exit-node \
    --accept-dns=false \
    --hostname=phalanx

echo ""
echo "       ✅ Tailscale connected"

# Get Tailscale IP
sleep 2
TS_IP=$(tailscale ip -4 2>/dev/null || echo "unknown")

# ── 4. Configure Phalanx to accept queries from Tailscale network ──
echo "[4/4] Configuring firewall for Tailscale..."

# Phalanx already listens on 0.0.0.0 (all interfaces), so the
# tailscale0 interface is automatically covered. We just need to
# ensure UFW allows traffic from the Tailscale subnet.
if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
    # Tailscale uses 100.64.0.0/10 (CGNAT range)
    ufw allow in on tailscale0 to any port 53 2>/dev/null || true
    ufw allow in on tailscale0 to any port 80 2>/dev/null || true
    ufw allow in on tailscale0 to any port 22 2>/dev/null || true
    echo "       ✅ Firewall rules added for Tailscale"
else
    echo "       UFW not active — Tailscale traffic allowed by default"
fi

echo ""
echo "========================================"
echo "  ✅ Tailscale VPN Active!"
echo ""
echo "  Tailscale IP:   ${TS_IP}"
echo "  Local IP:       ${PI_IP}"
echo "  Hostname:       phalanx"
echo ""
echo "  ── What to do next ──"
echo ""
echo "  1. APPROVE THE EXIT NODE:"
echo "     Go to https://login.tailscale.com/admin/machines"
echo "     Find 'phalanx', click ⋯ → Edit route settings"
echo "     Enable 'Use as exit node'"
echo ""
echo "  2. SET PHALANX AS YOUR TAILNET DNS:"
echo "     Go to https://login.tailscale.com/admin/dns"
echo "     Add a custom nameserver: ${TS_IP}"
echo "     Enable 'Override local DNS'"
echo ""
echo "  3. INSTALL TAILSCALE ON YOUR DEVICES:"
echo "     https://tailscale.com/download"
echo "     Sign in with the same account"
echo ""
echo "  Once configured, any device on your Tailscale"
echo "  network will route DNS through Phalanx — even"
echo "  on public WiFi, mobile data, or while traveling."
echo ""
echo "  Dashboard:  http://${TS_IP} (from any Tailscale device)"
echo "  SSH:        ssh michael@${TS_IP} (from anywhere)"
echo "========================================"
