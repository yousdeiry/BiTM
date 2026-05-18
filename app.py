require('dotenv').config();
const express = require('express');
const session = require('express-session');
const msal = require('@azure/msal-node');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuration MSAL
const msalConfig = {
    auth: {
        clientId: process.env.CLIENT_ID,
        authority: `https://login.microsoftonline.com/${process.env.TENANT_ID}`,
        clientSecret: process.env.CLIENT_SECRET
    },
    system: {
        loggerOptions: {
            loggerCallback(loglevel, message, containsPii) {
                console.log(message);
            },
            piiLoggingEnabled: false,
            logLevel: msal.LogLevel.Verbose,
        }
    }
};

const pca = new msal.ConfidentialClientApplication(msalConfig);

// Middleware
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false, // true en production avec HTTPS
        httpOnly: true,
        maxAge: 1000 * 60 * 60 // 1 heure
    }
}));

// ==================== ROUTES ====================

// Page d'accueil avec XSS VULNERABLE
app.get('/', (req, res) => {
    // XSS VULNERABLE - Paramètre 'debug' non sanitisé
    const debugData = req.query.debug || '';
    
    const html = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>SecureApp - Sign In</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 0;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
            }
            .container {
                background: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                max-width: 400px;
                width: 100%;
            }
            h1 {
                color: #333;
                margin-bottom: 10px;
                font-size: 28px;
            }
            .subtitle {
                color: #666;
                margin-bottom: 30px;
                font-size: 14px;
            }
            .btn-microsoft {
                width: 100%;
                padding: 15px;
                background: #2f2f2f;
                color: white;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                font-size: 16px;
                display: flex;
                align-items: center;
                justify-content: center;
                text-decoration: none;
                transition: background 0.3s;
            }
            .btn-microsoft:hover {
                background: #1a1a1a;
            }
            .ms-icon {
                width: 20px;
                height: 20px;
                margin-right: 10px;
            }
            .debug-panel {
                border: 2px dashed red;
                padding: 10px;
                margin-bottom: 20px;
                background: #fff3cd;
                font-size: 12px;
                border-radius: 5px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔒 SecureApp</h1>
            <p class="subtitle">Secure Access Portal</p>
            
            <!-- XSS VULNERABLE DEBUG PANEL -->
            ${debugData ? `
            <div class="debug-panel">
                <strong style="color: red;">⚠️ DEBUG MODE</strong><br>
                Debug: ${debugData}
            </div>
            ` : ''}
            
            <a href="/auth/signin" class="btn-microsoft">
                <svg class="ms-icon" viewBox="0 0 23 23">
                    <rect x="1" y="1" width="10" height="10" fill="#f25022"/>
                    <rect x="12" y="1" width="10" height="10" fill="#7fba00"/>
                    <rect x="1" y="12" width="10" height="10" fill="#00a4ef"/>
                    <rect x="12" y="12" width="10" height="10" fill="#ffb900"/>
                </svg>
                Sign in with Microsoft
            </a>
            
            <p style="text-align: center; margin-top: 20px; color: #999; font-size: 12px;">
                Protected by Microsoft MFA
            </p>
        </div>
    </body>
    </html>
    `;
    
    res.send(html);
});

// Initier la connexion Microsoft
app.get('/auth/signin', (req, res) => {
    const authCodeUrlParameters = {
        scopes: ['user.read', 'openid', 'profile', 'email'],
        redirectUri: process.env.REDIRECT_URI,
    };

    pca.getAuthCodeUrl(authCodeUrlParameters).then((response) => {
        res.redirect(response);
    }).catch((error) => {
        console.error(error);
        res.status(500).send('Error initiating authentication');
    });
});

// Callback après authentification Microsoft
app.get('/auth/redirect', (req, res) => {
    const tokenRequest = {
        code: req.query.code,
        scopes: ['user.read', 'openid', 'profile', 'email'],
        redirectUri: process.env.REDIRECT_URI,
    };

    pca.acquireTokenByCode(tokenRequest).then((response) => {
        // Stocker les infos utilisateur en session
        req.session.isAuthenticated = true;
        req.session.account = response.account;
        req.session.accessToken = response.accessToken;
        
        console.log('[AUTH] User authenticated:', response.account.username);
        
        res.redirect('/dashboard');
    }).catch((error) => {
        console.error('[AUTH] Error:', error);
        res.status(500).send('Authentication failed');
    });
});

// Dashboard (page protégée)
app.get('/dashboard', (req, res) => {
    if (!req.session.isAuthenticated) {
        return res.redirect('/');
    }
    
    const account = req.session.account;
    
    const html = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dashboard - SecureApp</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 0;
                background: #f5f5f5;
            }
            .header {
                background: white;
                padding: 20px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .container {
                max-width: 1200px;
                margin: 40px auto;
                padding: 0 20px;
            }
            .welcome-card {
                background: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                margin-bottom: 20px;
            }
            .info-card {
                background: #e8f5e9;
                padding: 20px;
                border-radius: 10px;
                margin-bottom: 20px;
            }
            .btn-logout {
                background: #d32f2f;
                color: white;
                padding: 10px 20px;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                text-decoration: none;
            }
            .success-icon {
                font-size: 48px;
                margin-bottom: 20px;
            }
        </style>
    </head>
    <body>
        <div class="header">
            <div>
                <strong>SecureApp</strong>
            </div>
            <a href="/auth/signout" class="btn-logout">Sign Out</a>
        </div>
        
        <div class="container">
            <div class="welcome-card">
                <div class="success-icon">✅</div>
                <h1>Welcome, ${account.name}!</h1>
                <p style="color: #666;">You have successfully authenticated with Microsoft MFA.</p>
            </div>
            
            <div class="info-card">
                <h3>Session Information</h3>
                <p><strong>Username:</strong> ${account.username}</p>
                <p><strong>Name:</strong> ${account.name}</p>
                <p><strong>Tenant ID:</strong> ${account.tenantId}</p>
                <p><strong>Home Account ID:</strong> ${account.homeAccountId}</p>
                <p><strong>Login Time:</strong> ${new Date().toISOString()}</p>
            </div>
        </div>
    </body>
    </html>
    `;
    
    res.send(html);
});

// Déconnexion
app.get('/auth/signout', (req, res) => {
    const logoutUri = `https://login.microsoftonline.com/${process.env.TENANT_ID}/oauth2/v2.0/logout`;
    
    req.session.destroy(() => {
        res.redirect(logoutUri);
    });
});

// Démarrage serveur
app.listen(PORT, '0.0.0.0', () => {
    console.log('\n' + '='.repeat(60));
    console.log('  Entra ID Demo App Started');
    console.log('='.repeat(60));
    console.log(`  App URL:         http://192.168.100.20:${PORT}`);
    console.log(`  XSS Test URL:    http://192.168.100.20:${PORT}/?debug=<test>`);
    console.log('='.repeat(60) + '\n');
});