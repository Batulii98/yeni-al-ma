from flask import Flask, request, redirect, url_for, session
from cryptography.fernet import Fernet
import json
import os
import base64
import hashlib

app = Flask(__name__)
app.secret_key = 'gizli_sess_key'
DATA_FILE = 'secrets.json'

# KDF ile anahtar üret (PBKDF2)
def derive_key(password):
    salt = b'sabit-tuz'  # Gerçekte her kullanıcıya özel olmalı
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100_000, dklen=32)
    return base64.urlsafe_b64encode(key)

def get_fernet(password):
    key = derive_key(password)
    return Fernet(key)

def load_secrets():
    if not os.path.exists(DATA_FILE):
        return []
    with open(DATA_FILE, 'r') as f:
        return json.load(f)

def save_secrets(secrets):
    with open(DATA_FILE, 'w') as f:
        json.dump(secrets, f)

def render_index():
    return '''
    <h2>Giriş Yap</h2>
    <form method="POST">
        <input type="password" name="master" placeholder="Ana Parola" required><br><br>
        <button type="submit">Giriş</button>
    </form>
    '''

def render_dashboard(decrypted_secrets, message=''):
    secret_list = ''.join(f'<li>{s}</li>' for s in decrypted_secrets)
    return f'''
    <h2>Şifrelerin</h2>
    {f'<p style="color:green;">{message}</p>' if message else ''}
    <form method="POST">
        <input type="text" name="secret" placeholder="Yeni şifre..." required>
        <button type="submit">Kaydet</button>
    </form>
    <h3>Kayıtlı Şifreler:</h3>
    <ul>{secret_list}</ul>
    <a href="/logout">Çıkış Yap</a>
    '''

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        session['master'] = request.form['master']
        return redirect(url_for('dashboard'))
    return render_index()

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'master' not in session:
        return redirect(url_for('index'))

    fernet = get_fernet(session['master'])
    secrets = load_secrets()

    if request.method == 'POST':
        new_secret = request.form['secret']
        encrypted = fernet.encrypt(new_secret.encode()).decode()
        secrets.append(encrypted)
        save_secrets(secrets)

    decrypted_secrets = []
    for enc in secrets:
        try:
            dec = fernet.decrypt(enc.encode()).decode()
            decrypted_secrets.append(dec)
        except:
            decrypted_secrets.append('[Çözülemedi]')

    return render_dashboard(decrypted_secrets, message='Şifre kaydedildi!' if request.method == 'POST' else '')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)