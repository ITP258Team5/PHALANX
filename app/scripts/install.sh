#!/usr/bin/env bash
set -euo pipefail

# Phalanx Application Installer
# Runs AFTER base system setup (base/install.sh)
# Installs the DNS proxy, blocklist engine, monitor, and web dashboard

INSTALL_DIR="/opt/phalanx"
SERVICE_NAME="phalanx"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="$(dirname "$SCRIPT_DIR")"

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

# ── 1. System dependencies ──
echo "[1/6] Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv dnsutils

# ── 2. Create install directory ──
echo "[2/6] Setting up ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}"/{data,blocklists,logs,gui/dist}

# Copy application files
cp "${APP_DIR}/main.py" "${INSTALL_DIR}/"
cp "${APP_DIR}/requirements.txt" "${INSTALL_DIR}/"
cp -r "${APP_DIR}/config" "${INSTALL_DIR}/"
cp -r "${APP_DIR}/core" "${INSTALL_DIR}/"
cp -r "${APP_DIR}/api" "${INSTALL_DIR}/"

# ── 3. Python dependencies ──
echo "[3/6] Installing Python packages..."
cd "${INSTALL_DIR}"
python3 -m pip install --break-system-packages -r requirements.txt

# ── 4. Install systemd service ──
echo "[4/6] Installing systemd service..."
cp "${APP_DIR}/scripts/phalanx.service" /etc/systemd/system/${SERVICE_NAME}.service
systemctl daemon-reload
systemctl enable ${SERVICE_NAME}

# ── 5. Configure DNS ──
echo "[5/6] Configuring local DNS..."

if systemctl is-active --quiet systemd-resolved; then
    systemctl stop systemd-resolved
    systemctl disable systemd-resolved
fi

cp /etc/resolv.conf /etc/resolv.conf.bak.phalanx 2>/dev/null || true
cat > /etc/resolv.conf << EOF
# Managed by Project Phalanx
nameserver 127.0.0.1
EOF

# ── 6. Verify firewall ──
echo "[6/6] Verifying firewall..."
if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
    ufw status | grep -q "80" || {
        SUBNET=$(echo "$STATIC_IP" | cut -d. -f1-3).0/24
        ufw allow from "$SUBNET" to any port 80
    }
    echo "Firewall OK"
else
    echo "UFW not active (base layer may not have run)"
fi

echo ""
echo "========================================"
echo "  Phalanx Application Installed!"
echo ""
echo "  Start now:   systemctl start ${SERVICE_NAME}"
echo "  View logs:   journalctl -u ${SERVICE_NAME} -f"
echo "  Dashboard:   http://${STATIC_IP}"
echo ""
echo "  NEXT STEP: Point your router's DNS"
echo "  server setting to ${STATIC_IP}"
echo "========================================"
