#!/bin/bash
# Script de démarrage du serveur VNC BiTM

echo "Démarrage du serveur VNC sur display :1..."
vncserver :1 -geometry 1920x1080 -depth 24 -rfbhost 0.0.0.0

echo "Serveur VNC démarré"
echo "Port: 5901"
echo "Display: :1"
