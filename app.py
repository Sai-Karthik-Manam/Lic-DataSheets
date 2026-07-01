from flask import Flask, request, send_file, jsonify, session, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive
import os
import json
import tempfile
import traceback
import threading
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import secrets
import re
from datetime import datetime, timedelta
import pytz
import bleach

load_dotenv()
app = Flask(__name__, static_folder='static/dist', static_url_path='')

SECRET_KEY = os.getenv('SECRET_KEY')
if not SECRET_KEY:
    SECRET_KEY = secrets.token_urlsafe(32)
app.secret_key = SECRET_KEY

app.config.update(
    SESSION_COOKIE_SECURE=os.getenv('FLASK_ENV') == 'production',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=24),
    MAX_CONTENT_LENGTH=10 * 1024 * 1024,
)

# CORS for React frontend
CORS(app, supports_credentials=True, origins=[
    'http://localhost:5173',
    'http://localhost:3000',
    os.getenv('FRONTEND_URL', 'http://localhost:5173')
])

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["500 per day", "100 per hour"],
)
limiter.init_app(app)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'pdf'}
MAX_FILE_SIZE = 10 * 1024 * 1024
UPLOAD_FOLDER = tempfile.gettempdir()
DOCUMENT_TYPES = ['datasheet', 'aadhaar', 'pan', 'bank_account']
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ROOT_FOLDER_ID = os.getenv('GOOGLE_DRIVE_FOLDER_ID', '')

USE_POSTGRESQL = bool(os.getenv('DB_HOST'))

if USE_POSTGRESQL:
    import psycopg2
    from psycopg2.extras import DictCursor
    def get_db_connection():
        return psycopg2.connect(
            host=os.getenv('DB_HOST'),
            database=os.getenv('DB_NAME'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            port=os.getenv('DB_PORT', 5432)
        )
else:
    import sqlite3
    def get_db_connection():
        conn = sqlite3.connect("database.db", timeout=15)
        conn.row_factory = sqlite3.Row
        return conn


# ─── Security Headers ────────────────────────────────────────────────────────

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


# ─── Helpers ─────────────────────────────────────────────────────────────────

def sanitize_input(text):
    if not text:
        return text
    return bleach.clean(text, strip=True)


def validate_and_sanitize_name(name):
    if not name or not isinstance(name, str):
        raise ValueError("Client name is required")
    name = sanitize_input(name)
    name = ' '.join(name.split())
    if len(name) < 2:
        raise ValueError("Client name must be at least 2 characters")
    if len(name) > 100:
        raise ValueError("Client name is too long (max 100 characters)")
    if not re.match(r'^[a-zA-Z0-9\s\-_.]+$', name):
        raise ValueError("Client name contains invalid characters")
    return name


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_file_size(file):
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    return size <= MAX_FILE_SIZE


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Authentication required', 'code': 401}), 401
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Authentication required', 'code': 401}), 401
        if session.get('role') != 'admin':
            return jsonify({'success': False, 'error': 'Admin access required', 'code': 403}), 403
        return f(*args, **kwargs)
    return decorated_function


def log_activity(action, details=""):
    conn = None
    cur = None
    try:
        user_id = session.get('user_id')
        ip_address = request.remote_addr
        conn = get_db_connection()
        cur = conn.cursor()
        now = datetime.now() if USE_POSTGRESQL else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if USE_POSTGRESQL:
            cur.execute(
                "INSERT INTO activity_logs (user_id, action, details, timestamp, ip_address) VALUES (%s, %s, %s, %s, %s)",
                (user_id, action, details, now, ip_address))
        else:
            cur.execute(
                "INSERT INTO activity_logs (user_id, action, details, timestamp, ip_address) VALUES (?, ?, ?, ?, ?)",
                (user_id, action, details, now, ip_address))
        conn.commit()
        app.logger.info(f"Activity logged: {action} by {session.get('username')}")
    except Exception as e:
        app.logger.error(f"Error logging activity: {str(e)}")
    finally:
        if cur:
            try: cur.close()
            except: pass
        if conn:
            try: conn.close()
            except: pass


def cleanup_temp_file(filepath):
    try:
        if filepath and os.path.exists(filepath):
            os.remove(filepath)
            return True
    except Exception as e:
        app.logger.warning(f"Could not remove temp file: {str(e)}")
    return False


FIXED_OTP_HASHES = {
    'veeru': 'scrypt:32768:8:1$ykHhADIwULYnK5sa$846d70329e5e6c137eba7a341074b74db298ee85d01f51e8ba8bf82938c14492d450f13ae202cf8833abfec77133e72b7b7635b426af5517fa376da9ad833a19',
    'karthik': 'scrypt:32768:8:1$gvuMQgCRYBL881sL$7d5128135bce79c2561dc3baf80e89ea5491f290572077d9a0b778c8482412dc31e7d0345b7907a31b0e90bb61ee8ea92dcafc85537bb4c452eee5352b22a5af'
}


# ─── Database Init ────────────────────────────────────────────────────────────

def init_db():
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        if USE_POSTGRESQL:
            cur.execute('''CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email VARCHAR(255),
                role VARCHAR(50) DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                failed_login_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP)''')

            cur.execute('''CREATE TABLE IF NOT EXISTS otps (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                otp VARCHAR(6) NOT NULL,
                expires_at TIMESTAMP NOT NULL)''')

            cur.execute('''CREATE TABLE IF NOT EXISTS clients (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) UNIQUE NOT NULL,
                folder_id VARCHAR(255) UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by INTEGER REFERENCES users(id))''')

            cur.execute('''CREATE TABLE IF NOT EXISTS documents (
                id SERIAL PRIMARY KEY,
                client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
                document_type VARCHAR(50) NOT NULL,
                file_id VARCHAR(255) UNIQUE NOT NULL,
                file_name TEXT NOT NULL,
                url TEXT NOT NULL,
                file_size BIGINT,
                mime_type VARCHAR(100),
                upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                uploaded_by INTEGER REFERENCES users(id),
                UNIQUE(client_id, document_type))''')

            cur.execute('''CREATE TABLE IF NOT EXISTS activity_logs (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                action VARCHAR(255) NOT NULL,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address VARCHAR(50))''')
        else:
            cur.execute('''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                email TEXT,
                role TEXT DEFAULT 'user',
                created_at TEXT NOT NULL,
                failed_login_attempts INTEGER DEFAULT 0,
                locked_until TEXT)''')

            cur.execute('''CREATE TABLE IF NOT EXISTS otps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                otp TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)''')

            cur.execute('''CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                folder_id TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                created_by INTEGER,
                FOREIGN KEY (created_by) REFERENCES users (id))''')

            cur.execute('''CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id INTEGER NOT NULL,
                document_type TEXT NOT NULL,
                file_id TEXT NOT NULL UNIQUE,
                file_name TEXT NOT NULL,
                url TEXT NOT NULL,
                file_size INTEGER,
                mime_type TEXT,
                upload_time TEXT NOT NULL,
                uploaded_by INTEGER,
                FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE,
                FOREIGN KEY (uploaded_by) REFERENCES users (id),
                UNIQUE(client_id, document_type))''')

            cur.execute('''CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                details TEXT,
                timestamp TEXT NOT NULL,
                ip_address TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id))''')

        indexes = [
            'CREATE INDEX IF NOT EXISTS idx_client_name ON clients(name)',
            'CREATE INDEX IF NOT EXISTS idx_folder_id ON clients(folder_id)',
            'CREATE INDEX IF NOT EXISTS idx_client_id ON documents(client_id)',
            'CREATE INDEX IF NOT EXISTS idx_doc_type ON documents(document_type)',
            'CREATE INDEX IF NOT EXISTS idx_username ON users(username)',
            'CREATE INDEX IF NOT EXISTS idx_activity_user ON activity_logs(user_id)',
        ]
        for idx_sql in indexes:
            try:
                cur.execute(idx_sql)
            except Exception as idx_err:
                app.logger.warning(f"Index creation warning: {idx_err}")

        # Seed default users if they don't exist (safe for Render ephemeral disk)
        now = datetime.now() if USE_POSTGRESQL else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        seed_users = [
            ('Karthik', generate_password_hash('Karthik@2005'), 'admin', 'karthik.manam1101@gmail.com'),
            ('Veeru',   generate_password_hash('Veeru@1977'),   'user',  'lic.datasheets@gmail.com'),
        ]
        for uname, pw, role, email in seed_users:
            try:
                if USE_POSTGRESQL:
                    cur.execute(
                        "INSERT INTO users (username, password, role, email, created_at) VALUES (%s,%s,%s,%s,%s) ON CONFLICT (username) DO NOTHING",
                        (uname, pw, role, email, now))
                else:
                    cur.execute(
                        "INSERT OR IGNORE INTO users (username, password, role, email, created_at) VALUES (?,?,?,?,?)",
                        (uname, pw, role, email, now))
            except Exception as seed_err:
                app.logger.warning(f"User seed warning for {uname}: {seed_err}")

        conn.commit()
        app.logger.info("[OK] Database initialized successfully")
    except Exception as e:
        app.logger.error(f"Database initialization error: {str(e)}")
        if conn:
            conn.rollback()
    finally:
        if cur:
            try: cur.close()
            except: pass
        if conn:
            try: conn.close()
            except: pass


try:
    init_db()
except Exception as e:
    app.logger.warning(f"Database initialization warning: {e}")


# ─── Google Drive Setup ───────────────────────────────────────────────────────

def setup_google_auth():
    try:
        client_id = os.getenv('GOOGLE_CLIENT_ID')
        client_secret = os.getenv('GOOGLE_CLIENT_SECRET')
        refresh_token = os.getenv('GOOGLE_REFRESH_TOKEN')
        if not all([client_id, client_secret, refresh_token]):
            app.logger.warning("Google Drive credentials not configured")
            return None
        client_config = {"installed": {
            "client_id": client_id, "client_secret": client_secret,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "redirect_uris": ["http://localhost"]
        }}
        client_secrets_file = os.path.join(tempfile.gettempdir(), 'client_secrets.json')
        with open(client_secrets_file, 'w') as f:
            json.dump(client_config, f)
        gauth = GoogleAuth(settings={
            'client_config_backend': 'file',
            'client_config_file': client_secrets_file,
            'save_credentials': False,
            'get_refresh_token': False
        })
        from oauth2client.client import OAuth2Credentials
        credentials = OAuth2Credentials(
            access_token=None, client_id=client_id, client_secret=client_secret,
            refresh_token=refresh_token, token_expiry=None,
            token_uri="https://oauth2.googleapis.com/token", user_agent=None
        )
        gauth.credentials = credentials
        gauth.Refresh()
        app.logger.info("Google Drive initialized successfully")
        return gauth
    except Exception as e:
        app.logger.error(f"Google Drive auth error: {str(e)}")
        return None


try:
    gauth = setup_google_auth()
    drive = GoogleDrive(gauth) if gauth else None
except Exception as e:
    app.logger.error(f"Google Drive initialization failed: {str(e)}")
    drive = None


# ─────────────────────────────────────────────────────────────────────────────
#  API ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/api/csrf-token', methods=['GET'])
def get_csrf_token():
    return jsonify({'csrf_token': 'not-required'})


@app.route('/api/me', methods=['GET'])
def get_me():
    if 'user_id' not in session:
        return jsonify({'authenticated': False}), 200
    return jsonify({
        'authenticated': True,
        'user_id': session.get('user_id'),
        'username': session.get('username'),
        'role': session.get('role'),
    })


# ─── Auth Routes ──────────────────────────────────────────────────────────────

@app.route('/api/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.get_json() or request.form
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'success': False, 'error': 'Please enter both username and password'}), 400

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        if USE_POSTGRESQL:
            cur = conn.cursor(cursor_factory=DictCursor)
            cur.execute(
                "SELECT id, username, password, role, email, failed_login_attempts, locked_until FROM users WHERE username = %s",
                (username,))
            user_row = cur.fetchone()
            user_dict = dict(user_row) if user_row else None
        else:
            cur = conn.cursor()
            cur.execute(
                "SELECT id, username, password, role, email, failed_login_attempts, locked_until FROM users WHERE username = ?",
                (username,))
            user_row = cur.fetchone()
            user_dict = {
                'id': user_row[0], 'username': user_row[1], 'password': user_row[2],
                'role': user_row[3], 'email': user_row[4],
                'failed_login_attempts': user_row[5], 'locked_until': user_row[6]
            } if user_row else None

        if not user_dict:
            return jsonify({'success': False, 'error': 'Invalid username or password'}), 401

        # Check if account is locked
        if user_dict['locked_until']:
            try:
                if USE_POSTGRESQL:
                    lock_time = user_dict['locked_until']
                    if hasattr(lock_time, 'tzinfo') and lock_time.tzinfo is not None:
                        lock_time = lock_time.replace(tzinfo=None)
                    current_time = datetime.now()
                else:
                    lock_time = datetime.strptime(str(user_dict['locked_until']), "%Y-%m-%d %H:%M:%S")
                    current_time = datetime.now()

                if lock_time > current_time:
                    return jsonify({
                        'success': False,
                        'error': 'Account locked due to too many failed attempts. Try again later.'
                    }), 403
            except Exception as e:
                app.logger.error(f"Lock time comparison error: {e}")

        if check_password_hash(user_dict['password'], password):
            # Reset failed attempts
            if USE_POSTGRESQL:
                cur.execute("UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = %s", (user_dict['id'],))
            else:
                cur.execute("UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?", (user_dict['id'],))
            conn.commit()
            
            # Mask email for frontend
            email_addr = user_dict.get('email', '')
            masked_email = email_addr
            if '@' in email_addr:
                parts = email_addr.split('@')
                masked_email = f"{parts[0][:2]}***@{parts[1]}"
                
            return jsonify({
                'success': True,
                'require_otp': True,
                'email': masked_email,
                'message': 'OTP verification required.'
            })
        else:
            # Increment failed attempts
            failed = user_dict['failed_login_attempts'] + 1
            lock_time = None
            if failed >= 5:
                lock_time = datetime.now() + timedelta(minutes=15)
            lock_time_str = lock_time if USE_POSTGRESQL else (
                lock_time.strftime("%Y-%m-%d %H:%M:%S") if lock_time else None)
            if USE_POSTGRESQL:
                cur.execute(
                    "UPDATE users SET failed_login_attempts = %s, locked_until = %s WHERE id = %s",
                    (failed, lock_time_str, user_dict['id']))
            else:
                cur.execute(
                    "UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?",
                    (failed, lock_time_str, user_dict['id']))
            conn.commit()
            msg = ('Account locked for 15 minutes.' if failed >= 5
                   else f'Invalid password. {5 - failed} attempt(s) remaining.')
            return jsonify({'success': False, 'error': msg}), 401

    except Exception as e:
        app.logger.error(f"Login error: {str(e)}")
        return jsonify({'success': False, 'error': 'An error occurred. Please try again.'}), 500
    finally:
        if cur:
            try: cur.close()
            except: pass
        if conn:
            try: conn.close()
            except: pass


@app.route('/api/verify-otp', methods=['POST'])
@limiter.limit("10 per minute")
def verify_otp():
    data = request.get_json() or request.form
    username = data.get('username', '').strip()
    otp_code = data.get('otp', '').strip()
    
    if not username or not otp_code:
        return jsonify({'success': False, 'error': 'Missing username or OTP'}), 400
        
    # Check static OTP
    user_lower = username.lower()
    expected_hash = FIXED_OTP_HASHES.get(user_lower)
    if not expected_hash or not check_password_hash(expected_hash, otp_code):
        return jsonify({'success': False, 'error': 'Invalid OTP code.'}), 401
        
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        if USE_POSTGRESQL:
            cur = conn.cursor(cursor_factory=DictCursor)
            cur.execute("SELECT id, username, role FROM users WHERE username = %s", (username,))
            user_row = cur.fetchone()
            user_dict = dict(user_row) if user_row else None
        else:
            cur = conn.cursor()
            cur.execute("SELECT id, username, role FROM users WHERE username = ?", (username,))
            user_row = cur.fetchone()
            user_dict = {
                'id': user_row[0], 'username': user_row[1], 'role': user_row[2]
            } if user_row else None
            
        if not user_dict:
            return jsonify({'success': False, 'error': 'Invalid user'}), 400
            
        # No otps DB operation needed for static OTPs
        # Just set session directly
        
        session['user_id'] = user_dict['id']
        session['username'] = user_dict['username']
        session['role'] = user_dict['role']
        session.permanent = True

        log_activity("LOGIN", f"User logged in via OTP: {username}")
        return jsonify({
            'success': True,
            'message': f'Welcome back, {username}!',
            'user': {
                'username': user_dict['username'],
                'role': user_dict['role'],
                'user_id': user_dict['id'],
            }
        })
        
    except Exception as e:
        app.logger.error(f"Verify OTP error: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error'}), 500
    finally:
        if cur:
            try: cur.close()
            except: pass
        if conn:
            try: conn.close()
            except: pass


@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    username = session.get('username')
    log_activity("LOGOUT", f"User logged out: {username}")
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out successfully'})


@app.route('/api/change-password', methods=['POST'])
@login_required
def change_password():
    data = request.get_json() or request.form
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')
    confirm_password = data.get('confirm_password', '')

    if not all([current_password, new_password, confirm_password]):
        return jsonify({'success': False, 'error': 'All fields are required'}), 400
    if len(new_password) < 6:
        return jsonify({'success': False, 'error': 'New password must be at least 6 characters'}), 400
    if new_password != confirm_password:
        return jsonify({'success': False, 'error': 'New passwords do not match'}), 400
    if new_password == current_password:
        return jsonify({'success': False, 'error': 'New password must be different from current password'}), 400

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        user_id = session.get('user_id')
        if USE_POSTGRESQL:
            cur.execute("SELECT password FROM users WHERE id = %s", (user_id,))
        else:
            cur.execute("SELECT password FROM users WHERE id = ?", (user_id,))
        user = cur.fetchone()
        if not user or not check_password_hash(user[0], current_password):
            return jsonify({'success': False, 'error': 'Current password is incorrect'}), 401
        hashed = generate_password_hash(new_password)
        if USE_POSTGRESQL:
            cur.execute("UPDATE users SET password = %s WHERE id = %s", (hashed, user_id))
        else:
            cur.execute("UPDATE users SET password = ? WHERE id = ?", (hashed, user_id))
        conn.commit()
        log_activity("PASSWORD_CHANGED", "User changed password")
        return jsonify({'success': True, 'message': 'Password changed successfully!'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur:
            try: cur.close()
            except: pass
        if conn:
            try: conn.close()
            except: pass


# ─── Dashboard ────────────────────────────────────────────────────────────────

@app.route('/api/dashboard', methods=['GET'])
@login_required
def dashboard():
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM clients")
        total_clients = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM documents")
        total_docs = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM users")
        total_users = cur.fetchone()[0]
        cur.execute("SELECT document_type, COUNT(*) FROM documents GROUP BY document_type")
        doc_distribution = [{'type': r[0], 'count': r[1]} for r in cur.fetchall()]

        if USE_POSTGRESQL:
            cur.execute("""
                SELECT c.name, c.created_at, COUNT(d.id) as doc_count
                FROM clients c LEFT JOIN documents d ON c.id = d.client_id
                GROUP BY c.id, c.name, c.created_at ORDER BY c.created_at DESC LIMIT 5
            """)
        else:
            cur.execute("""
                SELECT c.name, c.created_at, COUNT(d.id) as doc_count
                FROM clients c LEFT JOIN documents d ON c.id = d.client_id
                GROUP BY c.id ORDER BY c.created_at DESC LIMIT 5
            """)
        recent_clients = [
            {'name': r[0], 'created_at': str(r[1])[:10] if r[1] else '', 'doc_count': r[2]}
            for r in cur.fetchall()
        ]

        if USE_POSTGRESQL:
            cur.execute("""
                SELECT u.username, a.action, a.details, TO_CHAR(a.timestamp, 'YYYY-MM-DD HH24:MI:SS')
                FROM activity_logs a LEFT JOIN users u ON a.user_id = u.id
                ORDER BY a.timestamp DESC LIMIT 10
            """)
        else:
            cur.execute("""
                SELECT u.username, a.action, a.details, a.timestamp
                FROM activity_logs a LEFT JOIN users u ON a.user_id = u.id
                ORDER BY a.timestamp DESC LIMIT 10
            """)
        recent_activity = [
            {'username': r[0] or 'System', 'action': r[1], 'details': r[2], 'timestamp': str(r[3])}
            for r in cur.fetchall()
        ]

        return jsonify({
            'success': True,
            'stats': {
                'total_clients': total_clients,
                'total_docs': total_docs,
                'total_users': total_users,
                'doc_distribution': doc_distribution,
                'recent_clients': recent_clients,
                'recent_activity': recent_activity
            }
        })
    except Exception as e:
        app.logger.error(f"Dashboard error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur:
            try: cur.close()
            except: pass
        if conn:
            try: conn.close()
            except: pass


# ─── Upload ───────────────────────────────────────────────────────────────────

@app.route('/api/upload', methods=['POST'])
@login_required
@limiter.limit("10 per hour")
def upload():
    client_name = request.form.get('name', '').strip()
    if not client_name:
        return jsonify({'success': False, 'error': 'Client name is required'}), 400

    try:
        client_name = validate_and_sanitize_name(client_name)
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400

    if not drive:
        return jsonify({'success': False, 'error': 'Google Drive not configured'}), 500

    upload_results = []
    errors = []
    conn = None
    cur = None

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        if USE_POSTGRESQL:
            cur.execute("SELECT id, folder_id FROM clients WHERE name = %s", (client_name,))
        else:
            cur.execute("SELECT id, folder_id FROM clients WHERE name = ?", (client_name,))
        client = cur.fetchone()

        if not client:
            try:
                folder = drive.CreateFile({
                    'title': client_name,
                    'parents': [{'id': ROOT_FOLDER_ID}],
                    'mimeType': 'application/vnd.google-apps.folder'
                })
                folder.Upload()
                folder_id = folder['id']
            except Exception as e:
                return jsonify({'success': False, 'error': f'Error creating folder: {str(e)}'}), 500

            now = datetime.now() if USE_POSTGRESQL else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if USE_POSTGRESQL:
                cur.execute(
                    "INSERT INTO clients (name, folder_id, created_at, updated_at, created_by) VALUES (%s, %s, %s, %s, %s) RETURNING id",
                    (client_name, folder_id, now, now, session.get('user_id')))
                client_id = cur.fetchone()[0]
            else:
                cur.execute(
                    "INSERT INTO clients (name, folder_id, created_at, updated_at, created_by) VALUES (?, ?, ?, ?, ?)",
                    (client_name, folder_id, now, now, session.get('user_id')))
                client_id = cur.lastrowid
            conn.commit()
        else:
            client_id = client[0]
            folder_id = client[1]

        for doc_type in DOCUMENT_TYPES:
            file = request.files.get(doc_type)
            if not file or not file.filename:
                continue
            if not allowed_file(file.filename):
                errors.append(f'{doc_type}: Invalid file format')
                continue
            if not validate_file_size(file):
                errors.append(f'{doc_type}: File too large (max 10MB)')
                continue

            temp_path = os.path.join(UPLOAD_FOLDER, secure_filename(file.filename))
            try:
                file.save(temp_path)
                file_size = os.path.getsize(temp_path)
                file_mime = file.content_type
                gfile = drive.CreateFile({
                    'title': f"{client_name}_{doc_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg",
                    'parents': [{'id': folder_id}]
                })
                gfile.SetContentFile(temp_path)
                gfile.Upload()
                file_url = f"https://drive.google.com/uc?export=download&id={gfile['id']}"
                now = datetime.now() if USE_POSTGRESQL else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                if USE_POSTGRESQL:
                    cur.execute("""
                        INSERT INTO documents (client_id, document_type, file_id, file_name, url, file_size, mime_type, upload_time, uploaded_by)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (client_id, document_type) DO UPDATE SET
                            file_id = EXCLUDED.file_id, file_name = EXCLUDED.file_name,
                            url = EXCLUDED.url, upload_time = EXCLUDED.upload_time""",
                        (client_id, doc_type, gfile['id'], gfile['title'], file_url, file_size, file_mime, now, session.get('user_id')))
                else:
                    cur.execute("""
                        INSERT OR REPLACE INTO documents (client_id, document_type, file_id, file_name, url, file_size, mime_type, upload_time, uploaded_by)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (client_id, doc_type, gfile['id'], gfile['title'], file_url, file_size, file_mime, now, session.get('user_id')))
                upload_results.append({'type': doc_type, 'filename': gfile['title'], 'url': file_url})
            except Exception as e:
                errors.append(f'Error uploading {doc_type}: {str(e)}')
            finally:
                cleanup_temp_file(temp_path)

        now = datetime.now() if USE_POSTGRESQL else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if USE_POSTGRESQL:
            cur.execute("UPDATE clients SET updated_at = %s WHERE id = %s", (now, client_id))
        else:
            cur.execute("UPDATE clients SET updated_at = ? WHERE id = ?", (now, client_id))
        conn.commit()
        log_activity("DOCUMENT_UPLOADED", f"Uploaded {len(upload_results)} docs for {client_name}")

        return jsonify({
            'success': True,
            'message': f'Successfully uploaded {len(upload_results)} document(s)!',
            'uploaded': upload_results,
            'errors': errors,
            'client_name': client_name
        })
    except Exception as e:
        app.logger.error(f"Upload error: {str(e)}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur:
            try: cur.close()
            except: pass
        if conn:
            try: conn.close()
            except: pass


# ─── Fetch / Search ───────────────────────────────────────────────────────────

@app.route('/api/fetch-data', methods=['POST'])
@login_required
def fetch_data():
    data = request.get_json() or request.form
    client_name = data.get('name', '').strip()
    if not client_name:
        return jsonify({'success': False, 'error': 'Client name is required'}), 400

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        if USE_POSTGRESQL:
            cur.execute(
                "SELECT id, name, created_at, updated_at, folder_id FROM clients WHERE name ILIKE %s",
                (f'%{client_name}%',))
        else:
            cur.execute(
                "SELECT id, name, created_at, updated_at, folder_id FROM clients WHERE name LIKE ?",
                (f'%{client_name}%',))
        client_row = cur.fetchone()
        if not client_row:
            return jsonify({'success': False, 'not_found': True, 'name': client_name})

        client_id = client_row[0]
        if USE_POSTGRESQL:
            cur.execute(
                "SELECT document_type, file_id, file_name, url, file_size, upload_time FROM documents WHERE client_id = %s",
                (client_id,))
        else:
            cur.execute(
                "SELECT document_type, file_id, file_name, url, file_size, upload_time FROM documents WHERE client_id = ?",
                (client_id,))

        documents = {}
        for doc in cur.fetchall():
            documents[doc[0]] = {
                'file_id': doc[1], 'file_name': doc[2], 'url': doc[3],
                'file_size': doc[4] or 0,
                'upload_time': str(doc[5]) if doc[5] else '',
                'image_url': doc[3]
            }

        log_activity("DOCUMENTS_VIEWED", f"Viewed documents for {client_row[1]}")
        return jsonify({
            'success': True,
            'client': {
                'id': client_id,
                'name': client_row[1],
                'created_at': str(client_row[2])[:19] if client_row[2] else '',
                'updated_at': str(client_row[3])[:19] if client_row[3] else '',
                'folder_id': client_row[4],
                'documents': documents
            }
        })
    except Exception as e:
        app.logger.error(f"Fetch data error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur:
            try: cur.close()
            except: pass
        if conn:
            try: conn.close()
            except: pass


# ─── Clients ──────────────────────────────────────────────────────────────────

@app.route('/api/clients', methods=['GET'])
@login_required
def list_clients():
    conn = None
    cur = None
    try:
        search_query = request.args.get('search', '').strip()
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 20, type=int)
        offset = (page - 1) * limit
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Get total count
        count_base = "SELECT COUNT(DISTINCT c.id) FROM clients c"
        if search_query:
            if USE_POSTGRESQL:
                cur.execute(f"{count_base} WHERE c.name ILIKE %s", (f'%{search_query}%',))
            else:
                cur.execute(f"{count_base} WHERE c.name LIKE ?", (f'%{search_query}%',))
        else:
            cur.execute(count_base)
        total_count = cur.fetchone()[0]

        # Get records
        base = """SELECT c.id, c.name, c.created_at, c.updated_at, COUNT(d.id) as doc_count
                  FROM clients c LEFT JOIN documents d ON c.id = d.client_id"""
        if search_query:
            if USE_POSTGRESQL:
                cur.execute(f"{base} WHERE c.name ILIKE %s GROUP BY c.id ORDER BY c.updated_at DESC LIMIT %s OFFSET %s", (f'%{search_query}%', limit, offset))
            else:
                cur.execute(f"{base} WHERE c.name LIKE ? GROUP BY c.id ORDER BY c.updated_at DESC LIMIT ? OFFSET ?", (f'%{search_query}%', limit, offset))
        else:
            if USE_POSTGRESQL:
                cur.execute(f"{base} GROUP BY c.id ORDER BY c.updated_at DESC LIMIT %s OFFSET %s", (limit, offset))
            else:
                cur.execute(f"{base} GROUP BY c.id ORDER BY c.updated_at DESC LIMIT ? OFFSET ?", (limit, offset))

        clients = []
        for r in cur.fetchall():
            clients.append({
                'id': r[0], 'name': r[1],
                'created_at': str(r[2])[:10] if r[2] else '',
                'updated_at': str(r[3])[:10] if r[3] else '',
                'doc_count': r[4]
            })
            
        return jsonify({
            'success': True, 
            'clients': clients, 
            'search_query': search_query, 
            'is_search': bool(search_query),
            'pagination': {
                'page': page,
                'limit': limit,
                'total': total_count,
                'pages': (total_count + limit - 1) // limit
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur:
            try: cur.close()
            except: pass
        if conn:
            try: conn.close()
            except: pass


@app.route('/api/client/<int:client_id>/documents', methods=['GET'])
@login_required
def get_client_documents(client_id):
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        if USE_POSTGRESQL:
            cur.execute(
                "SELECT document_type, file_id, file_name, url, file_size, upload_time FROM documents WHERE client_id = %s",
                (client_id,))
        else:
            cur.execute(
                "SELECT document_type, file_id, file_name, url, file_size, upload_time FROM documents WHERE client_id = ?",
                (client_id,))
        docs = {}
        for doc in cur.fetchall():
            docs[doc[0]] = {
                'file_id': doc[1], 'file_name': doc[2], 'url': doc[3],
                'file_size': doc[4] or 0,
                'upload_time': str(doc[5]) if doc[5] else ''
            }
        return jsonify({'success': True, 'documents': docs})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur:
            try: cur.close()
            except: pass
        if conn:
            try: conn.close()
            except: pass


@app.route('/api/client/<int:client_id>/update-documents', methods=['POST'])
@login_required
def update_client_documents(client_id):
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        if USE_POSTGRESQL:
            cur.execute("SELECT id, folder_id FROM clients WHERE id = %s", (client_id,))
        else:
            cur.execute("SELECT id, folder_id FROM clients WHERE id = ?", (client_id,))
        client = cur.fetchone()
        if not client:
            return jsonify({'success': False, 'error': 'Client not found'}), 404

        folder_id = client[1]
        updated = []

        for doc_type in DOCUMENT_TYPES:
            if request.form.get(f'delete_{doc_type}') == 'true':
                try:
                    if USE_POSTGRESQL:
                        cur.execute(
                            "SELECT file_id FROM documents WHERE client_id = %s AND document_type = %s",
                            (client_id, doc_type))
                    else:
                        cur.execute(
                            "SELECT file_id FROM documents WHERE client_id = ? AND document_type = ?",
                            (client_id, doc_type))
                    doc_row = cur.fetchone()
                    if doc_row and drive:
                        try:
                            drive.CreateFile({'id': doc_row[0]}).Delete()
                        except: pass
                    if USE_POSTGRESQL:
                        cur.execute(
                            "DELETE FROM documents WHERE client_id = %s AND document_type = %s",
                            (client_id, doc_type))
                    else:
                        cur.execute(
                            "DELETE FROM documents WHERE client_id = ? AND document_type = ?",
                            (client_id, doc_type))
                    conn.commit()
                except Exception as e:
                    app.logger.error(f"Error deleting {doc_type}: {str(e)}")

            file = request.files.get(doc_type)
            if file and file.filename:
                if not allowed_file(file.filename) or not validate_file_size(file):
                    continue
                temp_path = os.path.join(UPLOAD_FOLDER, secure_filename(file.filename))
                try:
                    file.save(temp_path)
                    file_size = os.path.getsize(temp_path)
                    gfile = drive.CreateFile({
                        'title': f"{client_id}_{doc_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg",
                        'parents': [{'id': folder_id}]
                    })
                    gfile.SetContentFile(temp_path)
                    gfile.Upload()
                    file_url = f"https://drive.google.com/uc?export=download&id={gfile['id']}"
                    now = datetime.now() if USE_POSTGRESQL else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    if USE_POSTGRESQL:
                        cur.execute("""
                            INSERT INTO documents (client_id, document_type, file_id, file_name, url, file_size, mime_type, upload_time, uploaded_by)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (client_id, document_type) DO UPDATE SET
                                file_id = EXCLUDED.file_id, file_name = EXCLUDED.file_name,
                                url = EXCLUDED.url, upload_time = EXCLUDED.upload_time""",
                            (client_id, doc_type, gfile['id'], gfile['title'], file_url, file_size, file.content_type, now, session.get('user_id')))
                    else:
                        cur.execute("""
                            INSERT OR REPLACE INTO documents (client_id, document_type, file_id, file_name, url, file_size, mime_type, upload_time, uploaded_by)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            (client_id, doc_type, gfile['id'], gfile['title'], file_url, file_size, file.content_type, now, session.get('user_id')))
                    conn.commit()
                    updated.append(doc_type)
                except Exception as e:
                    app.logger.error(f"Error uploading {doc_type}: {str(e)}")
                finally:
                    cleanup_temp_file(temp_path)

        now = datetime.now() if USE_POSTGRESQL else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if USE_POSTGRESQL:
            cur.execute("UPDATE clients SET updated_at = %s WHERE id = %s", (now, client_id))
        else:
            cur.execute("UPDATE clients SET updated_at = ? WHERE id = ?", (now, client_id))
        conn.commit()
        log_activity("DOCUMENTS_UPDATED", f"Updated {len(updated)} docs for client {client_id}")
        return jsonify({'success': True, 'message': f'Updated {len(updated)} document(s)!', 'updated': updated})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur:
            try: cur.close()
            except: pass
        if conn:
            try: conn.close()
            except: pass


@app.route('/api/download-document', methods=['POST'])
@login_required
def download_document():
    data = request.get_json() or request.form
    file_id = data.get('file_id', '')
    if not file_id:
        return jsonify({'success': False, 'error': 'File ID is required'}), 400
    if not drive:
        return jsonify({'success': False, 'error': 'Google Drive not configured'}), 500
    try:
        file = drive.CreateFile({'id': file_id})
        file.FetchMetadata()
        temp_path = os.path.join(UPLOAD_FOLDER, secure_filename(file['title']))
        file.GetContentFile(temp_path)
        log_activity("DOCUMENT_DOWNLOADED", f"Downloaded: {file['title']}")
        response = send_file(temp_path, as_attachment=True, download_name=file['title'])
        @response.call_on_close
        def remove_file():
            cleanup_temp_file(temp_path)
        return response
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/delete-document', methods=['POST'])
@login_required
def delete_document():
    data = request.get_json() or request.form
    file_id = data.get('file_id', '')
    if not file_id:
        return jsonify({'success': False, 'error': 'File ID is required'}), 400

    conn = None
    cur = None
    try:
        if drive:
            drive.CreateFile({'id': file_id}).Delete()
        conn = get_db_connection()
        cur = conn.cursor()
        if USE_POSTGRESQL:
            cur.execute("DELETE FROM documents WHERE file_id = %s", (file_id,))
        else:
            cur.execute("DELETE FROM documents WHERE file_id = ?", (file_id,))
        conn.commit()
        log_activity("DOCUMENT_DELETED", f"Deleted: {file_id}")
        return jsonify({'success': True, 'message': 'Document deleted successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur:
            try: cur.close()
            except: pass
        if conn:
            try: conn.close()
            except: pass


@app.route('/api/delete-client', methods=['POST'])
@login_required
def delete_client():
    data = request.get_json() or request.form
    client_name = data.get('name', '').strip()
    if not client_name:
        return jsonify({'success': False, 'error': 'Client name is required'}), 400

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        if USE_POSTGRESQL:
            cur.execute("SELECT id, folder_id FROM clients WHERE name = %s", (client_name,))
        else:
            cur.execute("SELECT id, folder_id FROM clients WHERE name = ?", (client_name,))
        client = cur.fetchone()
        if not client:
            return jsonify({'success': False, 'error': 'Client not found'}), 404
        client_id, folder_id = client[0], client[1]
        if drive and folder_id:
            try:
                drive.CreateFile({'id': folder_id}).Delete()
            except: pass
        if USE_POSTGRESQL:
            cur.execute("DELETE FROM clients WHERE id = %s", (client_id,))
        else:
            cur.execute("DELETE FROM clients WHERE id = ?", (client_id,))
        conn.commit()
        log_activity("CLIENT_DELETED", f"Deleted client: {client_name}")
        return jsonify({'success': True, 'message': 'Client and all documents deleted successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur:
            try: cur.close()
            except: pass
        if conn:
            try: conn.close()
            except: pass


@app.route('/api/quick-search', methods=['GET'])
@login_required
def quick_search():
    query = request.args.get('q', '').strip()
    if len(query) < 2:
        return jsonify({'results': []})
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        if USE_POSTGRESQL:
            cur.execute("""
                SELECT c.name, c.updated_at, COUNT(d.id) as doc_count
                FROM clients c LEFT JOIN documents d ON c.id = d.client_id
                WHERE c.name ILIKE %s GROUP BY c.id, c.name, c.updated_at LIMIT 10""",
                (f'%{query}%',))
        else:
            cur.execute("""
                SELECT c.name, c.updated_at, COUNT(d.id) as doc_count
                FROM clients c LEFT JOIN documents d ON c.id = d.client_id
                WHERE c.name LIKE ? GROUP BY c.id, c.name LIMIT 10""",
                (f'%{query}%',))
        results = [
            {'name': r[0], 'updated_at': str(r[1])[:10] if r[1] else '', 'doc_count': r[2]}
            for r in cur.fetchall()
        ]
        return jsonify({'results': results})
    except Exception as e:
        return jsonify({'results': [], 'error': str(e)})
    finally:
        if cur:
            try: cur.close()
            except: pass
        if conn:
            try: conn.close()
            except: pass


@app.route('/api/manual-sync', methods=['POST'])
@login_required
def manual_sync():
    try:
        synced = sync_drive_to_database()
        log_activity("MANUAL_SYNC", f"Synced {synced} documents")
        return jsonify({'success': True, 'message': f'Synced {synced} documents from Google Drive', 'synced': synced})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ─── Admin Routes ─────────────────────────────────────────────────────────────

@app.route('/api/admin/export-clients', methods=['GET'])
@admin_required
def export_clients():
    import io
    import csv
    from flask import Response
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT c.name, c.created_at, c.updated_at, COUNT(d.id)
            FROM clients c LEFT JOIN documents d ON c.id = d.client_id
            GROUP BY c.id ORDER BY c.created_at DESC
        """)
        rows = cur.fetchall()
        
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Client Name', 'Created At', 'Last Updated At', 'Total Documents'])
        for row in rows:
            writer.writerow([row[0], str(row[1])[:19] if row[1] else '', str(row[2])[:19] if row[2] else '', row[3]])
            
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-disposition": "attachment; filename=clients_export.csv"}
        )
    except Exception as e:
        app.logger.error(f"Export error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur:
            try: cur.close()
            except: pass
        if conn:
            try: conn.close()
            except: pass

@app.route('/api/admin/dashboard', methods=['GET'])
@admin_required
def admin_dashboard():
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        if USE_POSTGRESQL:
            cur = conn.cursor(cursor_factory=DictCursor)
            cur.execute(
                "SELECT id, username, email, role, created_at, failed_login_attempts, locked_until FROM users ORDER BY created_at DESC")
            users_raw = [dict(u) for u in cur.fetchall()]
            for u in users_raw:
                u['created_at'] = str(u['created_at'])[:10] if u['created_at'] else ''
                u['locked_until'] = str(u['locked_until']) if u['locked_until'] else None
        else:
            cur = conn.cursor()
            cur.execute(
                "SELECT id, username, email, role, created_at, failed_login_attempts, locked_until FROM users ORDER BY created_at DESC")
            users_raw = [
                {'id': r[0], 'username': r[1], 'email': r[2], 'role': r[3],
                 'created_at': str(r[4])[:10] if r[4] else '',
                 'failed_login_attempts': r[5], 'locked_until': r[6]}
                for r in cur.fetchall()
            ]

        if USE_POSTGRESQL:
            cur.execute("SELECT COUNT(*) FROM users WHERE role = %s", ('admin',))
        else:
            cur.execute("SELECT COUNT(*) FROM users WHERE role = ?", ('admin',))
        admin_count = cur.fetchone()[0]

        if USE_POSTGRESQL:
            cur.execute("SELECT COUNT(*) FROM users WHERE role = %s", ('user',))
        else:
            cur.execute("SELECT COUNT(*) FROM users WHERE role = ?", ('user',))
        user_count = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM clients")
        clients_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM documents")
        docs_count = cur.fetchone()[0]

        return jsonify({
            'success': True,
            'users': users_raw,
            'stats': {
                'total_users': admin_count + user_count,
                'admin_users': admin_count,
                'regular_users': user_count,
                'total_clients': clients_count,
                'total_documents': docs_count
            },
            'current_user_id': session.get('user_id')
        })
    except Exception as e:
        app.logger.error(f"Admin dashboard error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur:
            try: cur.close()
            except: pass
        if conn:
            try: conn.close()
            except: pass


@app.route('/api/admin/user/add', methods=['POST'])
@admin_required
def admin_add_user():
    data = request.get_json() or request.form
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    role = data.get('role', 'user').strip()

    if not all([username, email, password]):
        return jsonify({'success': False, 'error': 'All fields are required'}), 400
    if len(username) < 3:
        return jsonify({'success': False, 'error': 'Username must be at least 3 characters'}), 400
    if len(password) < 6:
        return jsonify({'success': False, 'error': 'Password must be at least 6 characters'}), 400
    if role not in ['admin', 'user']:
        return jsonify({'success': False, 'error': 'Invalid role'}), 400

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        hashed = generate_password_hash(password)
        now = datetime.now() if USE_POSTGRESQL else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if USE_POSTGRESQL:
            cur.execute(
                "INSERT INTO users (username, password, email, role, created_at) VALUES (%s, %s, %s, %s, %s)",
                (username, hashed, email, role, now))
        else:
            cur.execute(
                "INSERT INTO users (username, password, email, role, created_at) VALUES (?, ?, ?, ?, ?)",
                (username, hashed, email, role, now))
        conn.commit()
        log_activity("USER_CREATED", f"Admin created user: {username} ({role})")
        return jsonify({'success': True, 'message': f'User {username} created successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': 'Username or email already exists'}), 409
    finally:
        if cur:
            try: cur.close()
            except: pass
        if conn:
            try: conn.close()
            except: pass


@app.route('/api/admin/user/<int:user_id>/role', methods=['POST'])
@admin_required
def change_user_role(user_id):
    data = request.get_json() or request.form
    new_role = data.get('role', '').strip()
    if new_role not in ['user', 'admin']:
        return jsonify({'success': False, 'error': 'Invalid role'}), 400
    if user_id == session.get('user_id') and new_role == 'user':
        return jsonify({'success': False, 'error': 'Cannot remove your own admin role'}), 400

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        if USE_POSTGRESQL:
            cur.execute("UPDATE users SET role = %s WHERE id = %s", (new_role, user_id))
        else:
            cur.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
        conn.commit()
        log_activity("ROLE_CHANGED", f"Role changed to {new_role} for user {user_id}")
        return jsonify({'success': True, 'message': f'Role changed to {new_role}'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur:
            try: cur.close()
            except: pass
        if conn:
            try: conn.close()
            except: pass


@app.route('/api/admin/user/<int:user_id>/password', methods=['POST'])
@admin_required
def admin_reset_password(user_id):
    data = request.get_json() or request.form
    new_password = data.get('new_password', '')
    if not new_password or len(new_password) < 6:
        return jsonify({'success': False, 'error': 'Password must be at least 6 characters'}), 400

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        hashed = generate_password_hash(new_password)
        if USE_POSTGRESQL:
            cur.execute(
                "UPDATE users SET password = %s, failed_login_attempts = 0, locked_until = NULL WHERE id = %s",
                (hashed, user_id))
            cur.execute("SELECT username FROM users WHERE id = %s", (user_id,))
        else:
            cur.execute(
                "UPDATE users SET password = ?, failed_login_attempts = 0, locked_until = NULL WHERE id = ?",
                (hashed, user_id))
            cur.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        user = cur.fetchone()
        conn.commit()
        log_activity("PASSWORD_RESET", f"Admin reset password for user {user_id}")
        return jsonify({'success': True, 'message': f'Password reset for {user[0] if user else "user"}'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur:
            try: cur.close()
            except: pass
        if conn:
            try: conn.close()
            except: pass


@app.route('/api/admin/user/<int:user_id>/unlock', methods=['POST'])
@admin_required
def unlock_user(user_id):
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        if USE_POSTGRESQL:
            cur.execute(
                "UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = %s",
                (user_id,))
        else:
            cur.execute(
                "UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?",
                (user_id,))
        conn.commit()
        log_activity("USER_UNLOCKED", f"User {user_id} unlocked")
        return jsonify({'success': True, 'message': 'User account unlocked'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur:
            try: cur.close()
            except: pass
        if conn:
            try: conn.close()
            except: pass


@app.route('/api/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    if user_id == session.get('user_id'):
        return jsonify({'success': False, 'error': 'Cannot delete your own account'}), 400
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        if USE_POSTGRESQL:
            cur.execute("SELECT username FROM users WHERE id = %s", (user_id,))
        else:
            cur.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        user = cur.fetchone()
        if USE_POSTGRESQL:
            cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        else:
            cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        log_activity("USER_DELETED", f"Deleted user: {user[0] if user else user_id}")
        return jsonify({'success': True, 'message': 'User deleted successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur:
            try: cur.close()
            except: pass
        if conn:
            try: conn.close()
            except: pass


@app.route('/api/admin/user/<int:user_id>/activity', methods=['GET'])
@admin_required
def user_activity(user_id):
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        if USE_POSTGRESQL:
            cur.execute("SELECT username FROM users WHERE id = %s", (user_id,))
        else:
            cur.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        user = cur.fetchone()
        if USE_POSTGRESQL:
            cur.execute(
                "SELECT action, details, timestamp, ip_address FROM activity_logs WHERE user_id = %s ORDER BY timestamp DESC LIMIT 100",
                (user_id,))
        else:
            cur.execute(
                "SELECT action, details, timestamp, ip_address FROM activity_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 100",
                (user_id,))
        activities = [
            {'action': r[0], 'details': r[1], 'timestamp': str(r[2]), 'ip': r[3]}
            for r in cur.fetchall()
        ]
        return jsonify({'success': True, 'username': user[0] if user else 'Unknown', 'activities': activities})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur:
            try: cur.close()
            except: pass
        if conn:
            try: conn.close()
            except: pass


# ─── Google Drive Sync ────────────────────────────────────────────────────────

def sync_drive_to_database():
    if not drive:
        return 0
    conn = None
    cur = None
    try:
        synced_count = 0
        query = f"'{ROOT_FOLDER_ID}' in parents and trashed=false"
        folder_list = drive.ListFile({'q': query, 'maxResults': 1000}).GetList()
        app.logger.info(f"Found {len(folder_list)} folders in Google Drive")
        conn = get_db_connection()
        cur = conn.cursor()

        for folder in folder_list:
            try:
                folder_name = folder['title']
                folder_id = folder['id']
                created_date = folder.get('createdDate', datetime.now().isoformat())[:19]
                modified_date = folder.get('modifiedDate', datetime.now().isoformat())[:19]

                if USE_POSTGRESQL:
                    cur.execute("SELECT id FROM clients WHERE name = %s", (folder_name,))
                else:
                    cur.execute("SELECT id FROM clients WHERE name = ?", (folder_name,))
                existing = cur.fetchone()

                if existing:
                    client_id = existing[0]
                    if USE_POSTGRESQL:
                        cur.execute(
                            "UPDATE clients SET folder_id = %s, updated_at = %s WHERE id = %s",
                            (folder_id, modified_date, client_id))
                    else:
                        cur.execute(
                            "UPDATE clients SET folder_id = ?, updated_at = ? WHERE id = ?",
                            (folder_id, modified_date, client_id))
                else:
                    if USE_POSTGRESQL:
                        cur.execute(
                            "INSERT INTO clients (name, folder_id, created_at, updated_at) VALUES (%s, %s, %s, %s) RETURNING id",
                            (folder_name, folder_id, created_date, modified_date))
                        client_id = cur.fetchone()[0]
                    else:
                        cur.execute(
                            "INSERT INTO clients (name, folder_id, created_at, updated_at) VALUES (?, ?, ?, ?)",
                            (folder_name, folder_id, created_date, modified_date))
                        client_id = cur.lastrowid
                    app.logger.info(f"Added client: {folder_name}")

                try:
                    files_list = drive.ListFile({
                        'q': f"'{folder_id}' in parents and trashed=false",
                        'maxResults': 1000
                    }).GetList()
                except:
                    files_list = []

                for file in files_list:
                    try:
                        file_lower = file['title'].lower()
                        if 'datasheet' in file_lower:
                            doc_type = 'datasheet'
                        elif 'aadhaar' in file_lower or 'aadhar' in file_lower:
                            doc_type = 'aadhaar'
                        elif 'pan' in file_lower:
                            doc_type = 'pan'
                        elif 'bank' in file_lower or 'account' in file_lower:
                            doc_type = 'bank_account'
                        else:
                            continue

                        file_url = f"https://drive.google.com/uc?export=download&id={file['id']}"
                        if USE_POSTGRESQL:
                            cur.execute("""
                                INSERT INTO documents (client_id, document_type, file_id, file_name, url, file_size, mime_type, upload_time)
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                                ON CONFLICT (client_id, document_type) DO UPDATE SET
                                    file_id = EXCLUDED.file_id, file_name = EXCLUDED.file_name,
                                    url = EXCLUDED.url""",
                                (client_id, doc_type, file['id'], file['title'], file_url,
                                 int(file.get('fileSize', 0)), file.get('mimeType', ''),
                                 file.get('createdDate', datetime.now().isoformat())[:19]))
                        else:
                            try:
                                cur.execute("""
                                    INSERT INTO documents (client_id, document_type, file_id, file_name, url, file_size, mime_type, upload_time)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                                    (client_id, doc_type, file['id'], file['title'], file_url,
                                     int(file.get('fileSize', 0)), file.get('mimeType', ''),
                                     file.get('createdDate', datetime.now().isoformat())[:19]))
                            except:
                                cur.execute("""
                                    UPDATE documents SET file_id=?, file_name=?, url=?
                                    WHERE client_id=? AND document_type=?""",
                                    (file['id'], file['title'], file_url, client_id, doc_type))
                        synced_count += 1
                    except:
                        continue

                conn.commit()
            except Exception as e:
                app.logger.error(f"Error syncing {folder.get('title', '?')}: {e}")
                conn.rollback()
                continue

        app.logger.info(f"Sync complete! {synced_count} documents synced")
        return synced_count
    except Exception as e:
        app.logger.error(f"Sync error: {str(e)}")
        return 0
    finally:
        if cur:
            try: cur.close()
            except: pass
        if conn:
            try: conn.close()
            except: pass


# ─── Error Handlers ───────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return jsonify({'success': False, 'error': 'Not found'}), 404

@app.errorhandler(413)
def too_large(e):
    return jsonify({'success': False, 'error': 'File too large. Maximum 10MB.'}), 413

@app.errorhandler(429)
def rate_limited(e):
    return jsonify({'success': False, 'error': 'Too many requests. Please slow down.'}), 429

@app.errorhandler(500)
def server_error(e):
    return jsonify({'success': False, 'error': 'Internal server error'}), 500


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_frontend(path):
    if path.startswith('api/'):
        return jsonify({'success': False, 'error': 'Not found'}), 404
    if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    else:
        return send_from_directory(app.static_folder, 'index.html')


# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == '__main__':
    def _run_initial_sync():
        try:
            app.logger.info("Starting initial sync on app startup...")
            synced = sync_drive_to_database()
            app.logger.info(f"Initial sync complete: {synced} documents synced")
        except Exception as e:
            app.logger.warning(f"Sync warning: {e}")

    sync_thread = threading.Thread(target=_run_initial_sync, daemon=True)
    sync_thread.start()

    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    port = int(os.getenv('PORT', 5000))
    app.logger.info(f"Starting Flask API on port {port} (debug={debug_mode})")
    app.run(debug=debug_mode, host='0.0.0.0', port=port)