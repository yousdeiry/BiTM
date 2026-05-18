from flask import Flask, request, render_template_string, session, redirect, url_for, jsonify
import pyotp
import secrets
from datetime import datetime

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Base de données simulée
users_db = {
    'alice@company.com': {
        'password': 'Password123!',
        'totp_secret': pyotp.random_base32(),  # Secret TOTP
        'name': 'Alice'
    }
}

# Template de login AVEC XSS VULNERABLE
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>SecureApp - Login</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial; 
            max-width: 400px; 
            margin: 100px auto; 
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 { 
            color: #333; 
            font-size: 24px;
            margin-bottom: 30px;
        }
        input { 
            width: 100%; 
            padding: 12px; 
            margin: 10px 0; 
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        button { 
            width: 100%; 
            padding: 12px; 
            background: #0066cc; 
            color: white; 
            border: none; 
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            margin-top: 10px;
        }
        button:hover {
            background: #0052a3;
        }
        .error { 
            color: #d93025; 
            padding: 10px; 
            background: #fce8e6; 
            border-radius: 4px;
            margin: 10px 0; 
        }
        .totp-step {
            display: none;
        }
        .totp-step.active {
            display: block;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 SecureApp Login</h1>
        
        <!-- XSS VULNERABLE - DEBUG PANEL -->
        <div style="border: 2px dashed red; padding: 10px; margin-bottom: 20px; font-size: 12px; background: #fff3cd;">
            <strong style="color: red;">⚠️ DEBUG MODE (XSS Vulnerable)</strong><br>
            Debug Data: {{ debug_data|safe }}
        </div>
        
        <!-- Step 1: Username + Password -->
        <div id="step1" class="step active">
            <form id="loginForm">
                <input type="email" id="username" placeholder="Email" required value="alice@company.com">
                <input type="password" id="password" placeholder="Password" required value="Password123!">
                <button type="submit">Continue</button>
            </form>
        </div>
        
        <!-- Step 2: TOTP Code -->
        <div id="step2" class="totp-step">
            <p style="color: #666; margin-bottom: 20px;">
                Enter the 6-digit code from your authenticator app
            </p>
            <form id="totpForm">
                <input type="text" id="totp_code" placeholder="000000" maxlength="6" required pattern="[0-9]{6}">
                <button type="submit">Verify</button>
            </form>
        </div>
        
        <div id="message"></div>
    </div>
    
    <script>
        // Step 1: Login with username + password
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            const res = await fetch('/api/auth/login', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username, password})
            });
            
            const data = await res.json();
            
            if (data.status === 'totp_required') {
                document.getElementById('step1').classList.remove('active');
                document.getElementById('step2').classList.add('active');
            } else {
                document.getElementById('message').innerHTML = '<div class="error">Invalid credentials</div>';
            }
        });
        
        // Step 2: Verify TOTP
        document.getElementById('totpForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const totp_code = document.getElementById('totp_code').value;
            
            const res = await fetch('/api/auth/verify-totp', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({totp_code})
            });
            
            const data = await res.json();
            
            if (data.status === 'success') {
                window.location.href = '/dashboard';
            } else {
                document.getElementById('message').innerHTML = '<div class="error">Invalid code</div>';
            }
        });
    </script>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard - SecureApp</title>
    <style>
        body { 
            font-family: Arial; 
            max-width: 800px; 
            margin: 50px auto; 
            padding: 20px;
        }
        .success { 
            color: #0f9d58; 
            font-size: 24px; 
            margin-bottom: 20px;
        }
        .info {
            background: #e8f0fe;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <h1>✅ Welcome, {{ name }}!</h1>
    <p class="success">Authentication successful!</p>
    
    <div class="info">
        <h3>Session Info:</h3>
        <p><strong>User:</strong> {{ username }}</p>
        <p><strong>Login Time:</strong> {{ login_time }}</p>
        <p><strong>Session ID:</strong> {{ session_id }}</p>
    </div>
    
    <p>
        <a href="/logout">Logout</a>
    </p>
</body>
</html>
"""

# Routes
@app.route('/')
def index():
    # XSS VULNERABLE - Pas de sanitization du paramètre 'debug'
    debug_data = request.args.get('debug', '')
    return render_template_string(LOGIN_TEMPLATE, debug_data=debug_data)

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    user = users_db.get(username)
    
    if user and user['password'] == password:
        session['username'] = username
        session['totp_verified'] = False
        return jsonify({'status': 'totp_required'})
    
    return jsonify({'status': 'error'}), 401

@app.route('/api/auth/verify-totp', methods=['POST'])
def verify_totp():
    data = request.json
    totp_code = data.get('totp_code')
    
    username = session.get('username')
    if not username:
        return jsonify({'status': 'error', 'message': 'No session'}), 401
    
    user = users_db[username]
    totp = pyotp.TOTP(user['totp_secret'])
    
    if totp.verify(totp_code, valid_window=1):
        session['totp_verified'] = True
        session['login_time'] = datetime.now().isoformat()
        return jsonify({'status': 'success'})
    
    return jsonify({'status': 'error', 'message': 'Invalid code'}), 401

@app.route('/dashboard')
def dashboard():
    if not session.get('totp_verified'):
        return redirect('/')
    
    username = session.get('username')
    user = users_db[username]
    
    return render_template_string(DASHBOARD_TEMPLATE,
        username=username,
        name=user['name'],
        login_time=session.get('login_time'),
        session_id=session.sid if hasattr(session, 'sid') else 'N/A'
    )

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# Route pour afficher le QR code TOTP (setup)
@app.route('/setup-totp/<username>')
def setup_totp(username):
    if username not in users_db:
        return "User not found", 404
    
    user = users_db[username]
    totp = pyotp.TOTP(user['totp_secret'])
    provisioning_uri = totp.provisioning_uri(
        name=username,
        issuer_name='SecureApp'
    )
    
    import qrcode
    import io
    import base64
    
    qr = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    qr.save(buf, format='PNG')
    buf.seek(0)
    qr_base64 = base64.b64encode(buf.read()).decode()
    
    return f"""
    <html>
    <head><title>Setup TOTP - {username}</title></head>
    <body style="font-family: Arial; max-width: 600px; margin: 50px auto; text-align: center;">
        <h1>Setup Two-Factor Authentication</h1>
        <p>Scan this QR code with Google Authenticator or any TOTP app:</p>
        <img src="data:image/png;base64,{qr_base64}" style="max-width: 300px;">
        <p><strong>Or enter this secret manually:</strong></p>
        <code style="background: #f5f5f5; padding: 10px; display: block; margin: 20px 0;">{user['totp_secret']}</code>
        <p><a href="/">Go to Login</a></p>
    </body>
    </html>
    """

if __name__ == '__main__':
    # Afficher les secrets TOTP au démarrage
    print("\n" + "="*60)
    print("  RP-TOTP Application Started")
    print("="*60)
    print("\nSetup TOTP for users:")
    for username, user in users_db.items():
        print(f"\n  User: {username}")
        print(f"  Password: {user['password']}")
        print(f"  TOTP Secret: {user['totp_secret']}")
        print(f"  Setup URL: http://192.168.100.20:5000/setup-totp/{username}")
    print("\n" + "="*60 + "\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)