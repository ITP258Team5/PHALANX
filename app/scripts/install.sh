#!/usr/bin/env bash
set -euo pipefail

# Phalanx Application Installer
# Runs AFTER base system setup (base/install.sh)
#
# SAFETY: Original DNS is kept until Phalanx is confirmed running.
# If the service fails to start, DNS is never switched and the Pi
# stays fully functional.

INSTALL_DIR="/opt/phalanx"
SERVICE_NAME="phalanx"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="$(dirname "$SCRIPT_DIR")"
DNS_SWITCHED=false

echo ""
echo "========================================"
echo "  Phalanx Application Installer"
echo "========================================"
echo ""

# Check root
if [[ $EUID -ne 0 ]]; then
   echo "Error: Run as root (sudo ./install.sh)"
   exit 1
fi

STATIC_IP=$(hostname -I | awk '{print $1}')

# ── Rollback on failure ──
rollback() {
    echo ""
    echo "⚠️  Installation failed. Rolling back..."

    if [[ "$DNS_SWITCHED" == true ]]; then
        echo "  Restoring original DNS..."
        if [[ -f /etc/resolv.conf.bak.phalanx ]]; then
            cp /etc/resolv.conf.bak.phalanx /etc/resolv.conf
            echo "  DNS restored."
        fi
    fi

    # Stop service if it was started
    systemctl stop ${SERVICE_NAME} 2>/dev/null || true

    echo ""
    echo "  Phalanx is NOT running. Your Pi is unchanged."
    echo "  Check logs: journalctl -u ${SERVICE_NAME} --no-pager -n 30"
    exit 1
}
trap rollback ERR

# ── 1. System dependencies ──
echo "[1/9] Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv dnsutils curl

# ── 2. Create install directory ──
echo "[2/9] Setting up ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}"/{data,blocklists,logs,gui/dist}

# Copy application files
cp "${APP_DIR}/main.py" "${INSTALL_DIR}/"
cp "${APP_DIR}/requirements.txt" "${INSTALL_DIR}/"
cp -r "${APP_DIR}/config" "${INSTALL_DIR}/"
cp -r "${APP_DIR}/core" "${INSTALL_DIR}/"
cp -r "${APP_DIR}/api" "${INSTALL_DIR}/"
cp -r "${APP_DIR}/scripts" "${INSTALL_DIR}/"

# ── 3. Python dependencies ──
echo "[3/9] Installing Python packages..."
cd "${INSTALL_DIR}"
python3 -m pip install --break-system-packages -r requirements.txt

# ── 4. Install systemd service ──
echo "[4/9] Installing systemd service..."
cp "${APP_DIR}/scripts/phalanx.service" /etc/systemd/system/${SERVICE_NAME}.service
systemctl daemon-reload
systemctl enable ${SERVICE_NAME}

# ── 5. Start service (DNS is still original — blocklist download works) ──
echo "[5/9] Starting Phalanx..."
systemctl start ${SERVICE_NAME}

# Wait for the service to come up and verify it's healthy
echo "       Waiting for service to initialize..."
RETRIES=0
MAX_RETRIES=15

while [[ $RETRIES -lt $MAX_RETRIES ]]; do
    sleep 2
    RETRIES=$((RETRIES + 1))

    # Check systemd thinks it's running
    if ! systemctl is-active --quiet ${SERVICE_NAME}; then
        echo "       Service not active yet (attempt ${RETRIES}/${MAX_RETRIES})..."
        continue
    fi

    # Check the API is responding
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:80/api/dashboard" 2>/dev/null || echo "000")
    if [[ "$HTTP_CODE" == "200" ]]; then
        echo "       ✅ Service is running and API is responding."
        break
    fi

    echo "       Waiting for API (attempt ${RETRIES}/${MAX_RETRIES}, HTTP ${HTTP_CODE})..."
done

# Final check
if ! systemctl is-active --quiet ${SERVICE_NAME}; then
    echo ""
    echo "❌ Phalanx failed to start."
    echo "   DNS has NOT been changed. Your Pi is fine."
    echo "   Debug: journalctl -u ${SERVICE_NAME} --no-pager -n 30"
    systemctl stop ${SERVICE_NAME} 2>/dev/null || true
    exit 1
fi

# Check blocklist loaded
BLOCKLIST_COUNT=$(curl -s "http://127.0.0.1:80/api/blocklist" 2>/dev/null | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(d.get('total_domains', 0))
except:
    print(0)
" 2>/dev/null || echo "0")

echo "       Blocklist: ${BLOCKLIST_COUNT} domains loaded."

if [[ "$BLOCKLIST_COUNT" -lt 100 ]]; then
    echo ""
    echo "⚠️  Warning: Blocklist has fewer than 100 domains."
    echo "   The initial download may still be in progress."
    echo "   This is normal on first boot — it will populate within a minute."
    echo ""
fi

# ── 6. NOW switch DNS (service is confirmed running) ──
echo "[6/9] Switching DNS to Phalanx..."

# Disable systemd-resolved if present
if systemctl is-active --quiet systemd-resolved; then
    systemctl stop systemd-resolved
    systemctl disable systemd-resolved
fi

# Back up original
cp /etc/resolv.conf /etc/resolv.conf.bak.phalanx 2>/dev/null || true
DNS_SWITCHED=true

cat > /etc/resolv.conf << EOF
# Managed by Project Phalanx
# Original backed up to /etc/resolv.conf.bak.phalanx
nameserver 127.0.0.1
EOF

# Verify DNS still works through Phalanx
echo "       Verifying DNS resolution through Phalanx..."
if nslookup google.com 127.0.0.1 &>/dev/null; then
    echo "       ✅ DNS resolution working."
else
    echo ""
    echo "⚠️  DNS resolution through Phalanx failed."
    echo "   Restoring original DNS..."
    cp /etc/resolv.conf.bak.phalanx /etc/resolv.conf
    DNS_SWITCHED=false
    echo "   Original DNS restored. Phalanx is running but not"
    echo "   handling this Pi's DNS. Check port 53 permissions."
    echo ""
fi

# ── 7. Install watchdog ──
echo "[7/9] Installing health watchdog..."
cp "${APP_DIR}/scripts/watchdog.py" "${INSTALL_DIR}/scripts/"
cp "${APP_DIR}/scripts/phalanx-watchdog.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable phalanx-watchdog
systemctl start phalanx-watchdog
echo "       Watchdog active (auto-restart + failsafe)"

# ── 8. Verify firewall ──
echo "[8/9] Verifying firewall..."
if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
    ufw status | grep -q "80" || {
        SUBNET=$(echo "$STATIC_IP" | cut -d. -f1-3).0/24
        ufw allow from "$SUBNET" to any port 80
    }
    # Ensure DHCP ports are open (67/68 UDP)
    ufw status | grep -q "67" || {
        SUBNET=$(echo "$STATIC_IP" | cut -d. -f1-3).0/24
        ufw allow from "$SUBNET" to any port 67 proto udp
        ufw allow from "$SUBNET" to any port 68 proto udp
    }
    echo "       Firewall OK"
else
    echo "       UFW not active (base layer may not have run)"
fi

# ── 9. DHCP auto-configuration ──
echo "[9/9] Setting up automatic DNS assignment..."
if [[ -f "${APP_DIR}/scripts/setup_dhcp.sh" ]]; then
    chmod +x "${APP_DIR}/scripts/setup_dhcp.sh"
    cp "${APP_DIR}/scripts/setup_dhcp.sh" "${INSTALL_DIR}/scripts/"
    echo ""
    echo "  To enable plug-and-play mode (all devices auto-use Phalanx):"
    echo "    sudo bash /opt/phalanx/scripts/setup_dhcp.sh"
    echo ""
    echo "  This makes Phalanx the DHCP server for your network."
    echo "  You will need to disable your router's DHCP after running it."
    echo ""
    read -p "  Run DHCP setup now? (y/n): " SETUP_DHCP
    if [[ "$SETUP_DHCP" == "y" ]]; then
        bash "${INSTALL_DIR}/scripts/setup_dhcp.sh"
        DHCP_ACTIVE=true
    fi
fi

echo ""
echo "========================================"
echo "  ✅ Phalanx Installed and Running!"
echo ""
echo "  Dashboard:   http://${STATIC_IP}"
echo "  Blocklist:   ${BLOCKLIST_COUNT} domains blocked"
echo "  Watchdog:    active (auto-restart + failsafe)"
if [[ "${DHCP_ACTIVE:-false}" == "true" ]]; then
echo "  DHCP:        active (devices auto-assigned)"
echo ""
echo "  Disable your router's DHCP server now."
echo "  All devices will automatically use Phalanx."
else
echo "  DHCP:        not configured (manual DNS or run setup_dhcp.sh)"
echo ""
echo "  NEXT STEP: Point your router's DNS to ${STATIC_IP}"
echo "  OR run: sudo bash /opt/phalanx/scripts/setup_dhcp.sh"
fi
echo ""
echo "  Logs:        journalctl -u ${SERVICE_NAME} -f"
echo "  Watchdog:    journalctl -u phalanx-watchdog -f"
echo "========================================"
