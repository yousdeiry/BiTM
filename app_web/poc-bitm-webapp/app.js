require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const OIDCStrategy = require('passport-azure-ad').OIDCStrategy;
const crypto = require('crypto');

const app = express();

// Parse les formulaires
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Configuration Azure AD depuis .env - VERSION FINALE
const config = {
  identityMetadata: `https://login.microsoftonline.com/${process.env.TENANT_ID}/v2.0/.well-known/openid-configuration`,
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  responseType: 'code',
  responseMode: 'query',
  redirectUrl: process.env.REDIRECT_URL,
  allowHttpForRedirectUrl: true,
  validateIssuer: true,
  issuer: `https://login.microsoftonline.com/${process.env.TENANT_ID}/v2.0`,
  passReqToCallback: false,
  scope: ['profile', 'offline_access', 'openid', 'email'],
  loggingLevel: 'error',
  nonceLifetime: null,
  nonceMaxAmount: 5,
  useCookieInsteadOfSession: false,
  cookieEncryptionKeys: [
    { 'key': '12345678901234567890123456789012', 'iv': '123456789012' }
  ],
  clockSkew: 300
};

// Configuration de la session
app.use(session({
  secret: 'votre-secret-super-securise-changez-moi',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: false,
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: 'lax'
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// Stratégie OIDC pour Azure AD
passport.use(new OIDCStrategy(config,
  function(iss, sub, profile, accessToken, refreshToken, done) {
    console.log('✅ Authentification réussie pour:', profile.displayName);
    
    if (!profile.oid) {
      return done(new Error("No OID found in user profile."));
    }
    
    return done(null, {
      oid: profile.oid,
      displayName: profile.displayName,
      email: profile._json.preferred_username || profile._json.email,
      profile: profile,
      accessToken: accessToken,
      refreshToken: refreshToken
    });
  }
));

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// Middleware pour vérifier l'authentification
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/');
}

// ===== ROUTES =====

// Page d'accueil
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="fr">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>PoC AiTM - Application Web Sécurisée</title>
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          min-height: 100vh;
          display: flex;
          justify-content: center;
          align-items: center;
        }
        .container {
          background: white;
          padding: 40px;
          border-radius: 10px;
          box-shadow: 0 10px 40px rgba(0,0,0,0.2);
          max-width: 500px;
          text-align: center;
        }
        h1 {
          color: #333;
          margin-bottom: 20px;
          font-size: 28px;
        }
        .subtitle {
          color: #666;
          margin-bottom: 30px;
          font-size: 16px;
        }
        .login-btn {
          background: #0078d4;
          color: white;
          padding: 15px 40px;
          border: none;
          border-radius: 5px;
          font-size: 16px;
          cursor: pointer;
          text-decoration: none;
          display: inline-block;
          transition: background 0.3s;
        }
        .login-btn:hover {
          background: #005a9e;
        }
        .badge {
          display: inline-block;
          background: #ffc107;
          color: #333;
          padding: 5px 15px;
          border-radius: 15px;
          font-size: 12px;
          font-weight: bold;
          margin-bottom: 20px;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="badge">🔒 PoC Cybersécurité</div>
        <h1>Application Web Sécurisée</h1>
        <p class="subtitle">
          Authentification via Microsoft Entra ID<br>
          avec Multi-Factor Authentication (MFA)
        </p>
        <a href="/login" class="login-btn">
          🔐 Se connecter avec Microsoft
        </a>
      </div>
    </body>
    </html>
  `);
});

// Route de connexion
app.get('/login', (req, res, next) => {
  console.log('🔐 Tentative de connexion...');
  
  passport.authenticate('azuread-openidconnect', {
    failureRedirect: '/',
    session: true
  })(req, res, next);
});

// Callback après authentification - IMPORTANT : GET au lieu de POST
app.get('/auth/callback', (req, res, next) => {
  console.log('📥 Callback reçu depuis Azure AD');
  
  passport.authenticate('azuread-openidconnect', {
    failureRedirect: '/',
    session: true
  })(req, res, next);
}, (req, res) => {
  console.log('✅ Authentification complète - Redirection vers dashboard');
  res.redirect('/dashboard');
});

// Page protégée - Dashboard
app.get('/dashboard', ensureAuthenticated, (req, res) => {
  console.log('📊 Affichage du dashboard pour:', req.user.displayName);
  
  const sessionCode = crypto.createHash('sha256')
    .update(req.sessionID)
    .digest('hex')
    .substring(0, 16)
    .toUpperCase();
  
  const formattedCode = sessionCode.match(/.{1,4}/g).join('-');
  
  const tokenPreview = req.user.accessToken 
    ? req.user.accessToken.substring(0, 50) + '...'
    : 'Non disponible';

  res.send(`
    <!DOCTYPE html>
    <html lang="fr">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Dashboard - Session Active</title>
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          background: #f5f5f5;
          padding: 20px;
        }
        .header {
          background: white;
          padding: 20px;
          border-radius: 10px;
          box-shadow: 0 2px 10px rgba(0,0,0,0.1);
          margin-bottom: 20px;
        }
        .header h1 {
          color: #333;
          margin-bottom: 10px;
        }
        .status {
          display: inline-block;
          background: #28a745;
          color: white;
          padding: 5px 15px;
          border-radius: 15px;
          font-size: 14px;
          font-weight: bold;
        }
        .card {
          background: white;
          padding: 25px;
          border-radius: 10px;
          box-shadow: 0 2px 10px rgba(0,0,0,0.1);
          margin-bottom: 20px;
        }
        .card h2 {
          color: #333;
          margin-bottom: 15px;
          font-size: 20px;
          border-bottom: 2px solid #0078d4;
          padding-bottom: 10px;
        }
        .user-info {
          display: grid;
          gap: 10px;
        }
        .info-row {
          display: grid;
          grid-template-columns: 150px 1fr;
          padding: 10px;
          background: #f8f9fa;
          border-radius: 5px;
        }
        .info-label {
          font-weight: bold;
          color: #666;
        }
        .info-value {
          color: #333;
        }
        .session-code {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          padding: 30px;
          border-radius: 10px;
          text-align: center;
          font-size: 32px;
          font-weight: bold;
          letter-spacing: 2px;
          font-family: 'Courier New', monospace;
          box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
        }
        .session-label {
          font-size: 14px;
          font-weight: normal;
          margin-bottom: 15px;
          opacity: 0.9;
        }
        .token-box {
          background: #fff3cd;
          border: 1px solid #ffc107;
          padding: 15px;
          border-radius: 5px;
          font-family: 'Courier New', monospace;
          font-size: 12px;
          word-break: break-all;
          color: #856404;
        }
        .warning {
          background: #fff3cd;
          border-left: 4px solid #ffc107;
          padding: 15px;
          margin-top: 20px;
          border-radius: 5px;
        }
        .warning strong {
          color: #856404;
        }
        .logout-btn {
          background: #dc3545;
          color: white;
          padding: 12px 30px;
          border: none;
          border-radius: 5px;
          font-size: 16px;
          cursor: pointer;
          text-decoration: none;
          display: inline-block;
          margin-top: 20px;
          transition: background 0.3s;
        }
        .logout-btn:hover {
          background: #c82333;
        }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>✅ Authentification réussie</h1>
        <span class="status">🔒 Session sécurisée active</span>
      </div>

      <div class="card">
        <h2>👤 Informations Utilisateur</h2>
        <div class="user-info">
          <div class="info-row">
            <div class="info-label">Nom complet :</div>
            <div class="info-value">${req.user.displayName}</div>
          </div>
          <div class="info-row">
            <div class="info-label">Email :</div>
            <div class="info-value">${req.user.email}</div>
          </div>
          <div class="info-row">
            <div class="info-label">ID Utilisateur :</div>
            <div class="info-value">${req.user.oid}</div>
          </div>
        </div>
      </div>

      <div class="card">
        <h2>🔑 Code de Session Active</h2>
        <div class="session-code">
          <div class="session-label">CODE SESSION</div>
          ${formattedCode}
        </div>
        <div class="warning">
          <strong>⚠️ Contexte du PoC :</strong> Ce code représente la session authentifiée. 
          Dans une attaque AiTM (Adversary-in-the-Middle), un attaquant intercepterait ce code 
          pour usurper la session.
        </div>
      </div>

      <div class="card">
        <h2>🎫 Token d'Accès (Extrait)</h2>
        <div class="token-box">
          ${tokenPreview}
        </div>
        <p style="margin-top: 10px; color: #666; font-size: 14px;">
          Ce token JWT contient les permissions et est utilisé pour accéder aux ressources protégées.
        </p>
      </div>

      <div style="text-align: center;">
        <a href="/logout" class="logout-btn">🚪 Se déconnecter</a>
      </div>
    </body>
    </html>
  `);
});

// Route de déconnexion
app.get('/logout', (req, res) => {
  console.log('🚪 Déconnexion');
  
  const logoutUrl = `https://login.microsoftonline.com/${process.env.TENANT_ID}/oauth2/v2.0/logout?post_logout_redirect_uri=${encodeURIComponent('http://localhost:3000')}`;
  
  req.logout((err) => {
    if (err) {
      return res.redirect('/');
    }
    req.session.destroy((err) => {
      res.redirect(logoutUrl);
    });
  });
});

// Gestion des erreurs
app.use((err, req, res, next) => {
  console.error('❌ ERREUR:', err.message);
  res.status(500).send(`
    <h1>Erreur</h1>
    <p>${err.message}</p>
    <a href="/">Retour à l'accueil</a>
  `);
});

// Démarrage du serveur
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('===========================================');
  console.log('🚀 Serveur démarré avec succès !');
  console.log('===========================================');
  console.log(`📍 URL : http://localhost:${PORT}`);
  console.log(`🏢 Tenant : ${process.env.DOMAIN}`);
  console.log(`🔐 Client ID : ${process.env.CLIENT_ID}`);
  console.log('===========================================');
  console.log('✅ Prêt pour les tests');
  console.log('===========================================\n');
});