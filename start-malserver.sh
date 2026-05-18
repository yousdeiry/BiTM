#!/bin/bash

# Script de démarrage MalSrv avec Xvfb
# Auteur: Yousef MULLA ISSA
# Date: 2026-05-18

set -e

echo "═══════════════════════════════════════════════════"
echo "  BitM+ MalServer Startup Script"
echo "═══════════════════════════════════════════════════"

# Configuration
XVFB_DISPLAY=:99
XVFB_RESOLUTION="1920x1080x24"
VNC_PORT=5900
BACKEND_DIR="$HOME/bitm-plus-poc/backend"

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Fonction log
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Vérifier dépendances
log "Checking dependencies..."

if ! command -v Xvfb &> /dev/null; then
    error "Xvfb not found. Install with: sudo apt-get install -y xvfb"
    exit 1
fi

if ! command -v x11vnc &> /dev/null; then
    error "x11vnc not found. Install with: sudo apt-get install -y x11vnc"
    exit 1
fi

if ! command -v node &> /dev/null; then
    error "Node.js not found. Install with: curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && sudo apt install -y nodejs"
    exit 1
fi

log "✓ All dependencies found"

# Arrêter processus existants
log "Stopping existing processes..."

pkill -f Xvfb || true
pkill -f x11vnc || true
pkill -f "node.*server.js" || true
sleep 2

# Démarrer Xvfb
log "Starting Xvfb on display $XVFB_DISPLAY..."

Xvfb $XVFB_DISPLAY -screen 0 $XVFB_RESOLUTION -ac +extension GLX +render -noreset &
XVFB_PID=$!

sleep 2

if ps -p $XVFB_PID > /dev/null; then
    log "✓ Xvfb started (PID: $XVFB_PID)"
else
    error "Failed to start Xvfb"
    exit 1
fi

# Démarrer x11vnc
log "Starting x11vnc on port $VNC_PORT..."

x11vnc -display $XVFB_DISPLAY -bg -nopw -listen 0.0.0.0 -xkb -forever -shared -rfbport $VNC_PORT

sleep 2

if pgrep -x x11vnc > /dev/null; then
    log "✓ x11vnc started on port $VNC_PORT"
else
    error "Failed to start x11vnc"
    exit 1
fi

# Démarrer window manager (optionnel, mais améliore compatibilité)
log "Starting Fluxbox window manager..."

DISPLAY=$XVFB_DISPLAY fluxbox &
sleep 1

# Démarrer Node.js backend
log "Starting MalServer..."

cd "$BACKEND_DIR"

export DISPLAY=$XVFB_DISPLAY

npm run dev &
NODE_PID=$!

sleep 3

if ps -p $NODE_PID > /dev/null; then
    log "✓ MalServer started (PID: $NODE_PID)"
else
    error "Failed to start MalServer"
    exit 1
fi

# Afficher informations
echo ""
echo "═══════════════════════════════════════════════════"
echo -e "${GREEN}✓ BitM+ MalServer Running${NC}"
echo "═══════════════════════════════════════════════════"
echo "  Xvfb Display:    $XVFB_DISPLAY"
echo "  VNC Server:      vnc://192.168.100.10:$VNC_PORT"
echo "  MalServer API:   http://localhost:3000"
echo "  Health Check:    http://localhost:3000/health"
echo ""
echo "  Process IDs:"
echo "    - Xvfb:        $XVFB_PID"
echo "    - x11vnc:      $(pgrep x11vnc)"
echo "    - Node.js:     $NODE_PID"
echo "═══════════════════════════════════════════════════"
echo ""
echo "To view BitM browser via VNC:"
echo "  vncviewer 192.168.100.10:$VNC_PORT"
echo ""
echo "To stop all services:"
echo "  pkill -f Xvfb; pkill -f x11vnc; pkill -f 'node.*server.js'"
echo ""
echo "Press Ctrl+C to stop (will keep services running in background)"
echo "═══════════════════════════════════════════════════"

# Attendre
wait $NODE_PID