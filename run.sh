#!/bin/bash

echo "======================================="
echo "   Phalanx Full Setup"
echo "======================================="
echo ""
echo "This will:"
echo "  1. Harden the base system (user, firewall, SSH)"
echo "  2. Install the Phalanx application (DNS proxy, dashboard)"
echo ""

read -p "Continue? (y/n): " CONFIRM
[[ "$CONFIRM" != "y" ]] && exit 1

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Layer 1: Base system hardening ──
echo ""
echo "═══════════════════════════════════════"
echo "  LAYER 1: Base System Setup"
echo "═══════════════════════════════════════"
echo ""

chmod +x "$SCRIPT_DIR/base/install.sh"
sudo bash "$SCRIPT_DIR/base/install.sh"

echo ""
echo "Base layer complete."
echo ""

# ── Layer 2: Phalanx application ──
echo "═══════════════════════════════════════"
echo "  LAYER 2: Phalanx Application"
echo "═══════════════════════════════════════"
echo ""

read -p "Install Phalanx application now? (y/n): " INSTALL_APP
if [[ "$INSTALL_APP" == "y" ]]; then
    chmod +x "$SCRIPT_DIR/app/scripts/install.sh"
    sudo bash "$SCRIPT_DIR/app/scripts/install.sh"

    echo ""
    read -p "Start Phalanx now? (y/n): " START_NOW
    if [[ "$START_NOW" == "y" ]]; then
        sudo systemctl start phalanx
        echo ""
        echo "Phalanx is running."
        echo "Dashboard: http://$(hostname -I | awk '{print $1}')"
    fi
fi

echo ""
echo "═══════════════════════════════════════"
echo "  ALL DONE"
echo "═══════════════════════════════════════"
echo ""
echo "SSH:       ssh $(whoami)@$(hostname -I | awk '{print $1}')"
echo "Dashboard: http://$(hostname -I | awk '{print $1}')"
echo ""
echo "Remember: Point your router's DNS to this device's IP."
