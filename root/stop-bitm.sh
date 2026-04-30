#!/bin/bash
# Script d'arrêt de l'infrastructure BiTM

echo "Arrêt du serveur VNC..."
vncserver -kill :1 2>/dev/null || true

echo "Arrêt de Websockify..."
pkill -f websockify 2>/dev/null || true

echo "Infrastructure BiTM arrêtée"
