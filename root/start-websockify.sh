#!/bin/bash
# Script de démarrage de Websockify

echo "Démarrage de Websockify..."
pkill -9 -f websockify
sleep 1
nohup websockify --web /home/root/noVNC 0.0.0.0:6080 localhost:5901 > /var/log/websockify.log 2>&1 &

WEBSOCKIFY_PID=$!
echo $WEBSOCKIFY_PID > /var/log/websockify.pid
sleep 2


if ps -p $WEBSOCKIFY_PID > /dev/null 2>&1; then
	echo "demarré"
else
	echo "erreur"
	exit 1
fi
