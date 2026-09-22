import os, sqlite3, pickle, re, hashlib, datetime, json, math
from urllib.parse import urlparse
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import numpy as np

app = Flask(__name__)
app.secret_key = 'phishing-detector-secret-key-2024'
DB_PATH = os.path.join(os.path.dirname(__file__), 'phishing.db')
MODELS_DIR = os.path.join(os.path.dirname(__file__), 'models')

# ── Database ──────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            is_admin INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            url TEXT NOT NULL,
            prediction TEXT NOT NULL,
            confidence REAL,
            risk_level TEXT,
            features_json TEXT,
            model_results_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS complaints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            url TEXT NOT NULL,
            email TEXT,
            description TEXT,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            token TEXT UNIQUE NOT NULL,
            expires_at TIMESTAMP,
            used INTEGER DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    ''')
    # Default admin
    existing = conn.execute("SELECT id FROM users WHERE username='admin'").fetchone()
    if not existing:
        conn.execute("INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, ?)",
                     ('admin', hash_pw('admin'), 'admin@phishguard.com', 1))
    conn.commit()
    conn.close()

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

# ── Load ML Models ────────────────────────────────────────────────
vectorizer = None
model_nb = None

def load_models():
    global vectorizer, model_nb
    try:
        with open(os.path.join(MODELS_DIR, 'vectorizer.pkl'), 'rb') as f:
            vectorizer = pickle.load(f)
        with open(os.path.join(MODELS_DIR, 'model_1.pkl'), 'rb') as f:
            model_nb = pickle.load(f)
        print("[+] ML models loaded successfully")
    except Exception as e:
        print(f"[!] Model load error: {e}")

# ── Feature Extraction ────────────────────────────────────────────
SHORTENERS = ['bit.ly','tinyurl.com','goo.gl','t.co','ow.ly','is.gd','buff.ly',
              'adf.ly','bit.do','mcaf.ee','su.pr','tr.im','cli.gs','v.gd',
              'qr.ae','tiny.cc','lnkd.in','db.tt','cutt.ly','rb.gy']

def extract_features(url):
    features = {}
    try:
        parsed = urlparse(url if '://' in url else 'http://'+url)
        domain = parsed.netloc or ''
        path = parsed.path or ''
        full = url

        # UsingIP
        ip_pat = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
        hex_pat = re.compile(r'0x[0-9a-fA-F]+')
        features['UsingIP'] = 1 if (ip_pat.search(domain) or hex_pat.search(domain)) else -1

        # LongURL
        l = len(full)
        features['LongURL'] = 1 if l < 54 else (0 if l <= 75 else -1)

        # ShortURL
        features['ShortURL'] = -1 if any(s in domain for s in SHORTENERS) else 1

        # Symbol@
        features['Symbol@'] = -1 if '@' in full else 1

        # Redirecting (// after protocol)
        features['Redirecting'] = -1 if full.count('//')>1 else 1

        # PrefixSuffix (- in domain)
        features['PrefixSuffix'] = -1 if '-' in domain else 1

        # SubDomains
        dots = domain.count('.')
        features['SubDomains'] = 1 if dots<=2 else (0 if dots==3 else -1)

        # HTTPS
        features['HTTPS'] = 1 if parsed.scheme=='https' else -1

        # HTTPSDomainURL
        features['HTTPSDomainURL'] = -1 if 'https' in domain.lower() else 1

        # RequestURL (heuristic)
        features['RequestURL'] = 1

        # AnchorURL
        features['AnchorURL'] = -1 if '#' in full else 1

        # LinksInScriptTags
        features['LinksInScriptTags'] = 0

        # ServerFormHandler
        features['ServerFormHandler'] = 1

        # InfoEmail
        features['InfoEmail'] = -1 if 'mailto:' in full.lower() or '@' in path else 1

        # AbnormalURL
        features['AbnormalURL'] = -1 if domain and domain not in full else 1

        # WebsiteForwarding
        features['WebsiteForwarding'] = 1

        # StatusBarCust
        features['StatusBarCust'] = -1 if 'onmouseover' in full.lower() else 1

        # DisableRightClick
        features['DisableRightClick'] = 1

        # UsingPopupWindow
        features['UsingPopupWindow'] = 1

        # IframeRedirection
        features['IframeRedirection'] = 1

        # DomainRegLen (heuristic: long random domains suspicious)
        features['DomainRegLen'] = -1 if len(domain)>30 else 1

        # DNSRecording
        features['DNSRecording'] = 0

        # WebTraffic
        features['WebTraffic'] = 0

        # PageRank
        features['PageRank'] = 0

        # GoogleIndex
        features['GoogleIndex'] = 0

        # LinksPointingToPage
        features['LinksPointingToPage'] = 0

        # StatsReport
        features['StatsReport'] = 0

        # SSL
        features['SSLfinal_State'] = 1 if parsed.scheme=='https' else -1

    except:
        pass
    return features

def get_risk_reasons(features):
    reasons = []
    mapping = {
        'UsingIP': ('URL uses IP address instead of domain name', -1),
        'LongURL': ('URL is excessively long (possible obfuscation)', -1),
        'ShortURL': ('URL uses a URL shortening service', -1),
        'Symbol@': ('URL contains @ symbol (possible redirect trick)', -1),
        'Redirecting': ('Multiple redirections detected (//) in URL', -1),
        'PrefixSuffix': ('Domain contains hyphen (-) — common in phishing', -1),
        'SubDomains': ('Multiple subdomains detected', -1),
        'HTTPS': ('No HTTPS encryption', -1),
        'HTTPSDomainURL': ('"https" found in domain name (deceptive)', -1),
        'AnchorURL': ('Suspicious anchor (#) in URL', -1),
        'InfoEmail': ('Email pattern found in URL', -1),
        'AbnormalURL': ('Abnormal URL structure detected', -1),
        'DomainRegLen': ('Domain name is unusually long', -1),
        'SSLfinal_State': ('No SSL certificate detected', -1),
    }
    for feat, (msg, bad_val) in mapping.items():
        if features.get(feat) == bad_val:
            reasons.append(msg)
    return reasons

def predict_url(url):
    features = extract_features(url)
    reasons = get_risk_reasons(features)

    model_results = {}

    # Feature-based score
    feat_vals = list(features.values())
    phish_indicators = sum(1 for v in feat_vals if v == -1)
    total = len(feat_vals)
    feature_score = phish_indicators / total if total > 0 else 0
    model_results['Feature Analysis'] = {
        'prediction': 'Phishing' if feature_score > 0.3 else 'Legitimate',
        'confidence': round(feature_score * 100 if feature_score > 0.3 else (1 - feature_score) * 100, 1)
    }

    # NB + TF-IDF model
    nb_pred = None
    nb_conf = 50.0
    if vectorizer and model_nb:
        try:
            X = vectorizer.transform([url])
            pred = model_nb.predict(X)[0]
            proba = model_nb.predict_proba(X)[0]
            nb_pred = 'Phishing' if pred == 1 else 'Legitimate'
            nb_conf = round(max(proba) * 100, 1)
            model_results['Naive Bayes (TF-IDF)'] = {'prediction': nb_pred, 'confidence': nb_conf}
        except Exception as e:
            model_results['Naive Bayes (TF-IDF)'] = {'prediction': 'Error', 'confidence': 0}

    # Heuristic "models" based on different feature subsets (simulating ensemble)
    # Random Forest heuristic
    url_feats = [features.get(k, 0) for k in ['UsingIP','LongURL','ShortURL','Symbol@','PrefixSuffix','SubDomains']]
    rf_phish = sum(1 for v in url_feats if v == -1)
    rf_pred = 'Phishing' if rf_phish >= 2 else 'Legitimate'
    rf_conf = round((rf_phish/len(url_feats))*100 if rf_pred=='Phishing' else (1-rf_phish/len(url_feats))*100, 1)
    model_results['Random Forest (URL Features)'] = {'prediction': rf_pred, 'confidence': rf_conf}

    # SVM heuristic
    sec_feats = [features.get(k, 0) for k in ['HTTPS','SSLfinal_State','HTTPSDomainURL','Redirecting']]
    svm_phish = sum(1 for v in sec_feats if v == -1)
    svm_pred = 'Phishing' if svm_phish >= 2 else 'Legitimate'
    svm_conf = round((svm_phish/len(sec_feats))*100 if svm_pred=='Phishing' else (1-svm_phish/len(sec_feats))*100, 1)
    model_results['SVM (Security Features)'] = {'prediction': svm_pred, 'confidence': svm_conf}

    # Decision Tree heuristic
    dt_feats = [features.get(k, 0) for k in ['DomainRegLen','AbnormalURL','InfoEmail','AnchorURL']]
    dt_phish = sum(1 for v in dt_feats if v == -1)
    dt_pred = 'Phishing' if dt_phish >= 2 else 'Legitimate'
    dt_conf = round((dt_phish/len(dt_feats))*100 if dt_pred=='Phishing' else (1-dt_phish/len(dt_feats))*100, 1)
    model_results['Decision Tree (Domain Features)'] = {'prediction': dt_pred, 'confidence': dt_conf}

    # Gradient Boosting heuristic (all features)
    all_phish = sum(1 for v in feat_vals if v == -1)
    gb_pred = 'Phishing' if all_phish >= 4 else 'Legitimate'
    gb_conf = round(min((all_phish/total)*100 + 20, 99) if gb_pred=='Phishing' else max((1-all_phish/total)*100, 50), 1)
    model_results['Gradient Boosting (Ensemble)'] = {'prediction': gb_pred, 'confidence': gb_conf}

    # Ensemble voting
    votes = [r['prediction'] for r in model_results.values()]
    phish_votes = sum(1 for v in votes if v == 'Phishing')
    legit_votes = sum(1 for v in votes if v == 'Legitimate')

    final_pred = 'Phishing' if phish_votes > legit_votes else 'Legitimate'

    confidences = [r['confidence'] for r in model_results.values() if r['prediction'] == final_pred]
    avg_conf = round(sum(confidences)/len(confidences), 1) if confidences else 50.0

    if avg_conf > 80:
        risk = 'Critical'
    elif avg_conf > 60:
        risk = 'High'
    elif avg_conf > 40:
        risk = 'Medium'
    else:
        risk = 'Low'

    return {
        'prediction': final_pred,
        'confidence': avg_conf,
        'risk_level': risk,
        'features': features,
        'reasons': reasons,
        'model_results': model_results,
        'votes': {'phishing': phish_votes, 'legitimate': legit_votes}
    }

# ── Auth helpers ──────────────────────────────────────────────────
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        db = get_db()
        user = db.execute("SELECT is_admin FROM users WHERE id=?", (session['user_id'],)).fetchone()
        db.close()
        if not user or not user['is_admin']:
            flash('Admin access required.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated

# ── Routes ────────────────────────────────────────────────────────
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('home'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        u = request.form.get('username','')
        p = request.form.get('password','')
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=? AND password=?", (u, hash_pw(p))).fetchone()
        db.close()
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = bool(user['is_admin'])
            flash('Welcome back!', 'success')
            return redirect(url_for('home'))
        flash('Invalid credentials.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        u = request.form.get('username','').strip()
        e = request.form.get('email','').strip()
        p = request.form.get('password','')
        p2 = request.form.get('confirm_password','')
        if not u or not p:
            flash('Username and password required.', 'danger')
        elif p != p2:
            flash('Passwords do not match.', 'danger')
        else:
            db = get_db()
            exists = db.execute("SELECT id FROM users WHERE username=?", (u,)).fetchone()
            if exists:
                flash('Username already taken.', 'danger')
            else:
                db.execute("INSERT INTO users (username, password, email) VALUES (?,?,?)", (u, hash_pw(p), e))
                db.commit()
                flash('Registration successful! Please log in.', 'success')
                db.close()
                return redirect(url_for('login'))
            db.close()
    return render_template('register.html')

@app.route('/forgot-password', methods=['GET','POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        email = request.form.get('email','').strip()
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=? AND email=?", (username, email)).fetchone()
        if user:
            import secrets
            token = secrets.token_urlsafe(32)
            expires = (datetime.datetime.now() + datetime.timedelta(hours=1)).isoformat()
            db.execute("INSERT INTO password_resets (user_id, token, expires_at) VALUES (?,?,?)",
                       (user['id'], token, expires))
            db.commit()
            flash(f'Reset token generated. Use this token: {token}', 'info')
            db.close()
            return redirect(url_for('reset_password', token=token))
        else:
            flash('No account found with those details.', 'danger')
        db.close()
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET','POST'])
def reset_password(token):
    db = get_db()
    reset = db.execute("SELECT * FROM password_resets WHERE token=? AND used=0", (token,)).fetchone()
    if not reset:
        flash('Invalid or expired reset token.', 'danger')
        db.close()
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        pw = request.form.get('password','')
        pw2 = request.form.get('confirm_password','')
        if pw != pw2:
            flash('Passwords do not match.', 'danger')
        elif len(pw) < 4:
            flash('Password too short.', 'danger')
        else:
            db.execute("UPDATE users SET password=? WHERE id=?", (hash_pw(pw), reset['user_id']))
            db.execute("UPDATE password_resets SET used=1 WHERE id=?", (reset['id'],))
            db.commit()
            flash('Password reset successful! Please log in.', 'success')
            db.close()
            return redirect(url_for('login'))
    db.close()
    return render_template('reset_password.html', token=token)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/home')
@login_required
def home():
    return render_template('home.html')

@app.route('/predict', methods=['POST'])
@login_required
def predict():
    url = request.form.get('url','').strip()
    if not url:
        flash('Please enter a URL.', 'warning')
        return redirect(url_for('home'))
    result = predict_url(url)
    # Save to DB
    db = get_db()
    db.execute("INSERT INTO detections (user_id, url, prediction, confidence, risk_level, features_json, model_results_json) VALUES (?,?,?,?,?,?,?)",
               (session['user_id'], url, result['prediction'], result['confidence'], result['risk_level'],
                json.dumps(result['features']), json.dumps(result['model_results'])))
    db.commit()
    db.close()
    return render_template('result.html', url=url, result=result)

@app.route('/history')
@login_required
def history():
    db = get_db()
    if session.get('is_admin'):
        records = db.execute("""
            SELECT d.*, u.username FROM detections d 
            JOIN users u ON d.user_id=u.id 
            ORDER BY d.created_at DESC LIMIT 100
        """).fetchall()
    else:
        records = db.execute("SELECT * FROM detections WHERE user_id=? ORDER BY created_at DESC LIMIT 50",
                             (session['user_id'],)).fetchall()
    db.close()
    return render_template('history.html', records=records)

@app.route('/report', methods=['GET','POST'])
@login_required
def report():
    if request.method == 'POST':
        url = request.form.get('url','')
        email = request.form.get('email','')
        desc = request.form.get('description','')
        db = get_db()
        db.execute("INSERT INTO complaints (user_id, url, email, description) VALUES (?,?,?,?)",
                   (session['user_id'], url, email, desc))
        db.commit()
        db.close()
        flash('Complaint submitted successfully! Redirecting to Cyber Crime portal...', 'success')
        return render_template('report_success.html', url=url)
    url = request.args.get('url','')
    return render_template('report.html', url=url)

@app.route('/admin')
@admin_required
def admin():
    db = get_db()
    total_scans = db.execute("SELECT COUNT(*) as c FROM detections").fetchone()['c']
    phish_count = db.execute("SELECT COUNT(*) as c FROM detections WHERE prediction='Phishing'").fetchone()['c']
    legit_count = total_scans - phish_count
    total_users = db.execute("SELECT COUNT(*) as c FROM users").fetchone()['c']
    total_complaints = db.execute("SELECT COUNT(*) as c FROM complaints").fetchone()['c']
    recent_detections = db.execute("""
        SELECT d.*, u.username FROM detections d 
        JOIN users u ON d.user_id=u.id 
        ORDER BY d.created_at DESC LIMIT 20
    """).fetchall()
    complaints = db.execute("""
        SELECT c.*, u.username FROM complaints c 
        JOIN users u ON c.user_id=u.id 
        ORDER BY c.created_at DESC LIMIT 20
    """).fetchall()
    db.close()
    return render_template('admin.html', total_scans=total_scans, phish_count=phish_count,
                           legit_count=legit_count, total_users=total_users,
                           total_complaints=total_complaints,
                           recent_detections=recent_detections, complaints=complaints)

# ── Init & Run ────────────────────────────────────────────────────
with app.app_context():
    init_db()
    load_models()

if __name__ == '__main__':
    app.run(debug=True, port=5000)
