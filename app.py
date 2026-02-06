from flask import Flask, render_template, request, send_file, jsonify, redirect, url_for, session, flash
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive
import os
import json
import tempfile
import traceback
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import secrets
import re
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import pytz
import bleach

load_dotenv()
app = Flask(__name__)

SECRET_KEY = os.getenv('SECRET_KEY')
if not SECRET_KEY:
    SECRET_KEY = secrets.token_urlsafe(32)
    print(f"WARNING: Using generated SECRET_KEY: {SECRET_KEY}")
app.secret_key = SECRET_KEY

# ============= ADD SESSION SECURITY CONFIGURATION HERE =============
app.config.update(
    SESSION_COOKIE_SECURE=False,  # HTTPS only in production
    SESSION_COOKIE_HTTPONLY=True,  # Prevent JavaScript access
    SESSION_COOKIE_SAMESITE='Lax',  # CSRF protection
    PERMANENT_SESSION_LIFETIME=timedelta(hours=24),
    MAX_CONTENT_LENGTH=10 * 1024 * 1024,  # 10MB max upload
)
# ===================================================================

csrf = CSRFProtect(app)
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"], storage_uri="memory://")

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'pdf'}
MAX_FILE_SIZE = 10 * 1024 * 1024
UPLOAD_FOLDER = tempfile.gettempdir()
DOCUMENT_TYPES = ['datasheet', 'aadhaar', 'pan', 'bank_account']
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ROOT_FOLDER_ID = os.getenv('GOOGLE_DRIVE_FOLDER_ID')
if not ROOT_FOLDER_ID:
    print("WARNING: GOOGLE_DRIVE_FOLDER_ID not set!")

# Email Configuration
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
SMTP_USERNAME = os.getenv('SMTP_USERNAME', 'lic.datasheets@gmail.com')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', '')

# Email addresses for OTP
USER_EMAIL = 'lic.datasheets@gmail.com'
ADMIN_EMAIL = 'karthik.manam1101@gmail.com'

USE_POSTGRESQL = os.getenv('DB_HOST') is not None

if USE_POSTGRESQL:
    print("Using PostgreSQL database")
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
    print("Using SQLite database")
    import sqlite3
    def get_db_connection():
        conn = sqlite3.connect("database.db")
        conn.row_factory = sqlite3.Row
        return conn


# ============= ADD SECURITY HEADERS FUNCTION HERE =============
@app.after_request
def set_security_headers(response):
    """Add security headers to all responses"""
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:;"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response
# ===============================================================


# ============= ADD INPUT SANITIZATION FUNCTION HERE =============
def sanitize_input(text):
    """Sanitize user input to prevent XSS attacks"""
    if not text:
        return text
    return bleach.clean(text, strip=True)


def validate_and_sanitize_name(name):
    """Validate and sanitize client names"""
    if not name or not isinstance(name, str):
        raise ValueError("Client name is required")
    
    # Sanitize first
    name = sanitize_input(name)
    
    # Remove extra whitespace
    name = ' '.join(name.split())
    
    if len(name) < 2:
        raise ValueError("Client name must be at least 2 characters")
    if len(name) > 100:
        raise ValueError("Client name is too long (max 100 characters)")
    
    # Only allow alphanumeric, spaces, hyphens, underscores, periods
    if not re.match(r'^[a-zA-Z0-9\s\-_.]+$', name):
        raise ValueError("Client name contains invalid characters")
    
    return name
# ================================================================


# ============= ADD ERROR HANDLER HERE =============
@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle file upload size limit exceeded"""
    flash('File too large! Maximum size is 10MB.', 'error')
    return redirect(request.referrer or url_for('upload_page')), 413


@app.errorhandler(500)
def internal_server_error(error):
    """Handle internal server errors"""
    app.logger.error(f"Internal server error: {str(error)}", exc_info=True)
    flash('An internal error occurred. Please try again.', 'error')
    return redirect(url_for('dashboard')), 500
# ==================================================


def init_db():
    """Initialize database - ONLY creates tables, NO default users"""
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        if USE_POSTGRESQL:
            # Create tables
            cur.execute('''CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY, 
                username VARCHAR(255) UNIQUE NOT NULL,
                password TEXT NOT NULL, 
                email VARCHAR(255), 
                role VARCHAR(50) DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                failed_login_attempts INTEGER DEFAULT 0, 
                locked_until TIMESTAMP)''')
            
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
            
            cur.execute('''CREATE TABLE IF NOT EXISTS otp_codes (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) NOT NULL,
                otp_code VARCHAR(6) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT FALSE)''')
        else:
            # SQLite tables
            cur.execute('''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT, 
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL, 
                email TEXT, 
                role TEXT DEFAULT 'user',
                created_at TEXT NOT NULL, 
                failed_login_attempts INTEGER DEFAULT 0, 
                locked_until TEXT)''')
            
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
            
            cur.execute('''CREATE TABLE IF NOT EXISTS otp_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                otp_code TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used INTEGER DEFAULT 0)''')
        
        # Create indexes
        cur.execute('CREATE INDEX IF NOT EXISTS idx_client_name ON clients(name)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_folder_id ON clients(folder_id)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_client_id ON documents(client_id)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_doc_type ON documents(document_type)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_username ON users(username)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_activity_user ON activity_logs(user_id)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_otp_username ON otp_codes(username)')
        
        conn.commit()
        print("Database tables initialized successfully")
        print("Note: No default users created. Use admin panel to add users.")
    except Exception as e:
        print(f"Database initialization error: {str(e)}")
        traceback.print_exc()
        if conn:
            conn.rollback()
    finally:
        if cur:
            try: 
                cur.close()
            except: 
                pass
        if conn:
            try: 
                conn.close()
            except: 
                pass

try:
    init_db()
except Exception as e:
    print(f"Database initialization warning: {e}")

def send_otp_email(email, otp_code, username):
    """Send OTP code via email"""
    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_USERNAME
        msg['To'] = email
        msg['Subject'] = 'LIC Manager - Your Login OTP Code'
        
        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <h2 style="color: #667eea;">LIC Manager - Login Verification</h2>
            <p>Hello <strong>{username}</strong>,</p>
            <p>Your One-Time Password (OTP) for login is:</p>
            <h1 style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                       color: white; padding: 20px; text-align: center; 
                       border-radius: 10px; letter-spacing: 5px;">{otp_code}</h1>
            <p><strong>Important:</strong></p>
            <ul>
                <li>This OTP is valid for <strong>5 minutes</strong></li>
                <li>Do not share this code with anyone</li>
                <li>If you didn't request this, please ignore this email</li>
            </ul>
            <p style="color: #666; font-size: 12px; margin-top: 30px;">
                This is an automated email from LIC Manager. Please do not reply.
            </p>
        </body>
        </html>
        """
        
        msg.attach(MIMEText(body, 'html'))
        
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
        
        return True
    except Exception as e:
        print(f"Email send error: {str(e)}")
        traceback.print_exc()
        return False


def generate_otp():
    """Generate 6-digit OTP"""
    return ''.join([str(secrets.randbelow(10)) for _ in range(6)])




# Define timezone - using UTC to match PostgreSQL
UTC = pytz.UTC
IST = pytz.timezone('Asia/Kolkata')

# ============= FIXED OTP FUNCTIONS =============
def store_otp(username, otp_code):
    """
    Store OTP in database - FIXED VERSION
    Key fix: Mark old OTPs as used instead of deleting them
    This prevents race conditions and timing issues
    """
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # CRITICAL FIX: Mark old OTPs as used instead of deleting
        # This prevents timing issues when generating multiple OTPs
        if USE_POSTGRESQL:
            cur.execute("""
                UPDATE otp_codes 
                SET used = TRUE 
                WHERE username = %s AND used = FALSE
            """, (username,))
        else:
            cur.execute("""
                UPDATE otp_codes 
                SET used = 1 
                WHERE username = ? AND used = 0
            """, (username,))
        
        # Store new OTP - Use PostgreSQL's NOW() function
        if USE_POSTGRESQL:
            cur.execute("""
                INSERT INTO otp_codes (username, otp_code, created_at, expires_at, used) 
                VALUES (%s, %s, NOW(), NOW() + INTERVAL '5 minutes', FALSE)
            """, (username, otp_code))
            
            # Get the actual stored values for logging
            cur.execute("""
                SELECT created_at, expires_at, 
                       EXTRACT(EPOCH FROM (expires_at - NOW())) as seconds_remaining
                FROM otp_codes 
                WHERE username = %s AND otp_code = %s AND used = FALSE
                ORDER BY created_at DESC
                LIMIT 1
            """, (username, otp_code))
            result = cur.fetchone()
            if result:
                created, expires, remaining = result
                print(f"✓ OTP stored for {username}: {otp_code}")
                print(f"  Created: {created}")
                print(f"  Expires: {expires}")
                print(f"  Valid for: {int(remaining)} seconds")
        else:
            # SQLite
            now = datetime.now()
            expires = now + timedelta(minutes=5)
            cur.execute("""
                INSERT INTO otp_codes (username, otp_code, created_at, expires_at, used) 
                VALUES (?, ?, ?, ?, ?)
            """, (username, otp_code, now.strftime("%Y-%m-%d %H:%M:%S"), 
                  expires.strftime("%Y-%m-%d %H:%M:%S"), 0))
            print(f"✓ OTP stored for {username}: {otp_code}")
        
        conn.commit()
        return True
    except Exception as e:
        print(f"❌ Store OTP error: {str(e)}")
        traceback.print_exc()
        if conn:
            conn.rollback()
        return False
    finally:
        if cur:
            try: 
                cur.close()
            except: 
                pass
        if conn:
            try: 
                conn.close()
            except: 
                pass


def verify_otp(username, otp_code):
    """
    Verify OTP code - FIXED VERSION
    Key fix: Better error handling and clearer logging
    """
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        if USE_POSTGRESQL:
            # Use PostgreSQL's NOW() for all time comparisons
            cur.execute("""
                SELECT 
                    id, 
                    expires_at, 
                    used,
                    created_at,
                    EXTRACT(EPOCH FROM (expires_at - NOW())) as seconds_remaining,
                    EXTRACT(EPOCH FROM (NOW() - created_at)) as seconds_old
                FROM otp_codes 
                WHERE username = %s AND otp_code = %s AND used = FALSE
                ORDER BY created_at DESC 
                LIMIT 1
            """, (username, otp_code))
            
            result = cur.fetchone()
            
            if not result:
                print(f"❌ OTP not found or already used: username={username}, code={otp_code}")
                # Show recent OTPs for debugging
                cur.execute("""
                    SELECT otp_code, used,
                           EXTRACT(EPOCH FROM (expires_at - NOW())) as remaining
                    FROM otp_codes 
                    WHERE username = %s 
                    ORDER BY created_at DESC 
                    LIMIT 3
                """, (username,))
                existing = cur.fetchall()
                if existing:
                    print(f"  Recent OTPs for {username}:")
                    for code, used, rem in existing:
                        status = "USED" if used else ("EXPIRED" if rem <= 0 else f"{int(rem)}s left")
                        print(f"    - {code}: {status}")
                return False
            
            otp_id, expires_at, used, created_at, seconds_remaining, seconds_old = result
            
            print(f"🔍 OTP Verification for {username}:")
            print(f"   Code: {otp_code}")
            print(f"   Created: {created_at} (DB time)")
            print(f"   Expires: {expires_at} (DB time)")
            print(f"   Age: {int(seconds_old)} seconds")
            print(f"   Remaining: {int(seconds_remaining)} seconds")
            
            # Check if expired
            if seconds_remaining <= 0:
                print(f"❌ OTP expired {int(abs(seconds_remaining))} seconds ago")
                return False
            
            # Valid OTP - mark as used
            cur.execute("UPDATE otp_codes SET used = TRUE WHERE id = %s", (otp_id,))
            conn.commit()
            print(f"✅ OTP verified successfully!")
            return True
            
        else:
            # SQLite version
            cur.execute("""
                SELECT id, expires_at, used 
                FROM otp_codes 
                WHERE username = ? AND otp_code = ? AND used = 0
                ORDER BY created_at DESC 
                LIMIT 1
            """, (username, otp_code))
            
            result = cur.fetchone()
            
            if not result:
                print(f"❌ OTP not found or already used: username={username}, code={otp_code}")
                return False
            
            otp_id = result[0]
            expires_at = datetime.strptime(result[1], "%Y-%m-%d %H:%M:%S")
            now = datetime.now()
            
            if now > expires_at:
                print(f"❌ OTP expired")
                return False
            
            cur.execute("UPDATE otp_codes SET used = 1 WHERE id = ?", (otp_id,))
            conn.commit()
            print(f"✅ OTP verified successfully for {username}")
            return True
        
    except Exception as e:
        print(f"❌ Verify OTP error: {str(e)}")
        traceback.print_exc()
        return False
    finally:
        if cur:
            try: 
                cur.close()
            except: 
                pass
        if conn:
            try: 
                conn.close()
            except: 
                pass

# Google Drive Setup

def setup_google_auth():
    try:
        client_id = os.getenv('GOOGLE_CLIENT_ID')
        client_secret = os.getenv('GOOGLE_CLIENT_SECRET')
        refresh_token = os.getenv('GOOGLE_REFRESH_TOKEN')
        
        if not all([client_id, client_secret, refresh_token]):
            print("Warning: Google Drive credentials not configured")
            return None
        
        client_config = {"installed": {
            "client_id": client_id, 
            "client_secret": client_secret,
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
            access_token=None, 
            client_id=client_id, 
            client_secret=client_secret,
            refresh_token=refresh_token, 
            token_expiry=None,
            token_uri="https://oauth2.googleapis.com/token", 
            user_agent=None
        )
        gauth.credentials = credentials
        gauth.Refresh()
        print("Google Drive authentication successful")
        return gauth
    except Exception as e:
        print(f"Google Drive auth error: {str(e)}")
        return None

try:
    gauth = setup_google_auth()
    drive = GoogleDrive(gauth) if gauth else None
    print("Google Drive initialized")
except Exception as e:
    print(f"Google Drive initialization failed: {str(e)}")
    drive = None


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
            flash('Please login to access this page.', 'error')
            return redirect(url_for('login'))
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
            cur.execute("INSERT INTO activity_logs (user_id, action, details, timestamp, ip_address) VALUES (%s, %s, %s, %s, %s)",
                (user_id, action, details, now, ip_address))
        else:
            cur.execute("INSERT INTO activity_logs (user_id, action, details, timestamp, ip_address) VALUES (?, ?, ?, ?, ?)",
                (user_id, action, details, now, ip_address))
        conn.commit()
    except Exception as e:
        print(f"Error logging activity: {str(e)}")
    finally:
        if cur:
            try: 
                cur.close()
            except: 
                pass
        if conn:
            try: 
                conn.close()
            except: 
                pass


def cleanup_temp_file(filepath):
    try:
        if filepath and os.path.exists(filepath):
            os.remove(filepath)
            return True
    except Exception as e:
        print(f"Warning: Could not remove temp file: {str(e)}")
    return False


def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please login first.', 'error')
                return redirect(url_for('login'))
            
            if session.get('role') != required_role:
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('dashboard'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def admin_required(f):
    return role_required('admin')(f)

# ============= ROUTES =============

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return render_template('login.html')
        
        # No username restrictions - check against database
        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            if USE_POSTGRESQL:
                cur = conn.cursor(cursor_factory=DictCursor)
                cur.execute("SELECT id, username, password, role, email, failed_login_attempts, locked_until FROM users WHERE username = %s", (username,))
                user_row = cur.fetchone()
                user_dict = dict(user_row) if user_row else None
            else:
                cur.execute("SELECT id, username, password, role, email, failed_login_attempts, locked_until FROM users WHERE username = ?", (username,))
                user_row = cur.fetchone()
                user_dict = {'id': user_row[0], 'username': user_row[1], 'password': user_row[2], 'role': user_row[3],
                    'email': user_row[4], 'failed_login_attempts': user_row[5], 'locked_until': user_row[6]} if user_row else None
            
            if user_dict:
                # Check if account is locked
                if user_dict['locked_until']:
                    try:
                        lock_time = user_dict['locked_until'] if USE_POSTGRESQL else datetime.strptime(str(user_dict['locked_until']), "%Y-%m-%d %H:%M:%S")
                        if lock_time and lock_time > datetime.now():
                            flash('Account locked. Try again later.', 'error')
                            return render_template('login.html')
                    except Exception as e:
                        print(f"Lock check error: {e}")
                
                # Verify password
                if check_password_hash(user_dict['password'], password):
                    # Generate and send OTP
                    otp_code = generate_otp()
                    
                    # Use the email from database
                    email = user_dict['email']
                    if not email:
                        flash('No email configured for this account. Contact administrator.', 'error')
                        return render_template('login.html')
                    
                    # Store OTP
                    if store_otp(username, otp_code):
                        # Send OTP email
                        if send_otp_email(email, otp_code, username):
                            # Store user info in session temporarily
                            session['pending_user_id'] = user_dict['id']
                            session['pending_username'] = user_dict['username']
                            session['pending_role'] = user_dict['role']
                            
                            # Reset failed attempts
                            if USE_POSTGRESQL:
                                cur.execute("UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = %s", (user_dict['id'],))
                            else:
                                cur.execute("UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?", (user_dict['id'],))
                            conn.commit()
                            
                            flash(f'OTP sent to {email}. Please check your email.', 'success')
                            return redirect(url_for('verify_otp_page'))
                        else:
                            flash('Failed to send OTP. Please check email configuration.', 'error')
                    else:
                        flash('Failed to generate OTP. Please try again.', 'error')
                else:
                    # Wrong password
                    failed_attempts = user_dict['failed_login_attempts'] + 1
                    lock_time = None
                    if failed_attempts >= 5:
                        lock_time = datetime.now() + timedelta(minutes=15)
                        flash('Too many failed attempts. Account locked for 15 minutes.', 'error')
                    else:
                        flash(f'Invalid password. {5 - failed_attempts} attempts remaining.', 'error')
                    
                    lock_time_str = lock_time if USE_POSTGRESQL else (lock_time.strftime("%Y-%m-%d %H:%M:%S") if lock_time else None)
                    if USE_POSTGRESQL:
                        cur.execute("UPDATE users SET failed_login_attempts = %s, locked_until = %s WHERE id = %s",
                            (failed_attempts, lock_time_str, user_dict['id']))
                    else:
                        cur.execute("UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?",
                            (failed_attempts, lock_time_str, user_dict['id']))
                    conn.commit()
            else:
                # Username not found
                flash('Invalid username or password.', 'error')
        except Exception as e:
            print(f"Login error: {str(e)}")
            traceback.print_exc()
            flash('An error occurred. Please try again.', 'error')
        finally:
            if cur:
                try: 
                    cur.close()
                except: 
                    pass
            if conn:
                try: 
                    conn.close()
                except: 
                    pass
    
    return render_template('login.html')


@app.route('/verify-otp', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def verify_otp_page():
    if 'pending_user_id' not in session:
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        otp_code = request.form.get('otp_code', '').strip()
        
        if not otp_code or len(otp_code) != 6:
            flash('Please enter a valid 6-digit OTP.', 'error')
            return render_template('verify_otp.html')
        
        username = session.get('pending_username')
        
        if verify_otp(username, otp_code):
            # Login successful
            session['user_id'] = session.pop('pending_user_id')
            session['username'] = session.pop('pending_username')
            session['role'] = session.pop('pending_role')
            
            log_activity("LOGIN", f"User logged in with OTP: {username}")
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid or expired OTP. Please try again.', 'error')
            return render_template('verify_otp.html')
    
    return render_template('verify_otp.html')


@app.route('/resend-otp', methods=['POST'])
@limiter.limit("3 per minute")
@csrf.exempt
def resend_otp():
    """
    Resend OTP - FIXED VERSION
    Properly handles email lookup from database
    """
    if 'pending_user_id' not in session:
        return jsonify({'success': False, 'error': 'Session expired. Please login again.'}), 400
    
    conn = None
    cur = None
    try:
        username = session.get('pending_username')
        user_id = session.get('pending_user_id')
        
        if not username or not user_id:
            return jsonify({'success': False, 'error': 'Session data incomplete'}), 400
        
        # FIXED: Get email from database instead of using role-based lookup
        conn = get_db_connection()
        cur = conn.cursor()
        
        if USE_POSTGRESQL:
            cur.execute("SELECT email FROM users WHERE id = %s", (user_id,))
        else:
            cur.execute("SELECT email FROM users WHERE id = ?", (user_id,))
        
        user = cur.fetchone()
        if not user or not user[0]:
            return jsonify({'success': False, 'error': 'No email configured for this account'}), 400
        
        email = user[0]
        
        # Generate new OTP
        otp_code = generate_otp()
        
        print(f"Resending OTP to {email} for user {username}")
        
        # Store and send OTP
        if store_otp(username, otp_code):
            if send_otp_email(email, otp_code, username):
                log_activity("OTP_RESENT", f"OTP resent for {username}")
                return jsonify({'success': True, 'message': 'OTP sent successfully'}), 200
            else:
                return jsonify({'success': False, 'error': 'Failed to send email'}), 500
        else:
            return jsonify({'success': False, 'error': 'Failed to generate OTP'}), 500
    except Exception as e:
        print(f"Resend OTP error: {str(e)}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur:
            try: 
                cur.close()
            except: 
                pass
        if conn:
            try: 
                conn.close()
            except: 
                pass


@app.route('/logout')
@login_required
def logout():
    username = session.get('username')
    log_activity("LOGOUT", f"User logged out: {username}")
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    flash('New registrations are not allowed. Please use existing accounts.', 'error')
    return redirect(url_for('login'))


@app.route('/forgot_password', methods=['GET', 'POST'])
@limiter.limit("3 per hour")
def forgot_password():
    flash('Password reset is disabled. Please contact administrator.', 'error')
    return redirect(url_for('login'))


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not current_password or not new_password or not confirm_password:
            flash('All fields are required.', 'error')
            return render_template('change_password.html')
        if len(new_password) < 6:
            flash('New password must be at least 6 characters.', 'error')
            return render_template('change_password.html')
        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return render_template('change_password.html')
        if new_password == current_password:
            flash('New password must be different from current password.', 'error')
            return render_template('change_password.html')
        
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
                flash('Current password is incorrect.', 'error')
                return render_template('change_password.html')
            
            hashed_new_password = generate_password_hash(new_password)
            if USE_POSTGRESQL:
                cur.execute("UPDATE users SET password = %s WHERE id = %s", (hashed_new_password, user_id))
            else:
                cur.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_new_password, user_id))
            conn.commit()
            log_activity("PASSWORD_CHANGED", "User changed password")
            flash('Password changed successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            print(f"Change password error: {str(e)}")
            flash('An error occurred. Please try again.', 'error')
            return render_template('change_password.html')
        finally:
            if cur:
                try: 
                    cur.close()
                except: 
                    pass
            if conn:
                try: 
                    conn.close()
                except: 
                    pass
    
    return render_template('change_password.html')

@app.route('/dashboard')
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
        
        stats = {
            'total_clients': total_clients,
            'total_docs': total_docs,
            'total_users': total_users,
            'recent_activity': [],
            'doc_distribution': [],
            'recent_clients': []
        }
        
        return render_template('dashboard.html', stats=stats)
    except Exception as e:
        print(f"Dashboard error: {str(e)}")
        flash(f"Error loading dashboard: {str(e)}", "error")
        return render_template('dashboard.html', stats={})
    finally:
        if cur:
            try: 
                cur.close()
            except: 
                pass
        if conn:
            try: 
                conn.close()
            except: 
                pass


@app.route('/upload_page')
@login_required
def upload_page():
    return render_template('upload.html')


@app.route('/fetch')
@login_required
def fetch_page():
    return render_template('fetch.html')


@app.route('/clients')
@login_required
def list_clients():
    conn = None
    cur = None
    try:
        sort_by = request.args.get('sort', 'updated_at')
        order = request.args.get('order', 'desc')
        search_query = request.args.get('search', '').strip()
        
        valid_sorts = ['name', 'created_at', 'updated_at']
        if sort_by not in valid_sorts:
            sort_by = 'updated_at'
        
        order_sql = 'ASC' if order.lower() == 'asc' else 'DESC'
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        base_query = """SELECT c.id, c.name, c.created_at, c.updated_at, COUNT(d.id) as doc_count
            FROM clients c LEFT JOIN documents d ON c.id = d.client_id"""
        
        if search_query:
            if USE_POSTGRESQL:
                query = f"{base_query} WHERE c.name ILIKE %s GROUP BY c.id ORDER BY c.{sort_by} {order_sql}"
                cur.execute(query, (f'%{search_query}%',))
            else:
                query = f"{base_query} WHERE c.name LIKE ? GROUP BY c.id ORDER BY c.{sort_by} {order_sql}"
                cur.execute(query, (f'%{search_query}%',))
        else:
            query = f"{base_query} GROUP BY c.id ORDER BY c.updated_at DESC LIMIT 20"
            cur.execute(query)
        
        clients = cur.fetchall()
        clients_list = [tuple(client) for client in clients] if USE_POSTGRESQL else clients
        
        return render_template('clients.html', clients=clients_list, sort_by=sort_by,
            order=order_sql.lower(), search_query=search_query, is_search=bool(search_query))
    except Exception as e:
        print(f"List clients error: {str(e)}")
        traceback.print_exc()
        flash(f"Error: {str(e)}", "error")
        return render_template('clients.html', clients=[], is_search=False)
    finally:
        if cur:
            try: 
                cur.close()
            except: 
                pass
        if conn:
            try: 
                conn.close()
            except: 
                pass


@app.route('/upload', methods=['POST'])
@login_required
@limiter.limit("10 per hour")
def upload():
    client_name = request.form.get('name', '').strip()
    if not client_name:
        flash('Client name is required.', 'error')
        return redirect(url_for('upload_page'))
    
    try:
        client_name = validate_and_sanitize_name(client_name)
    except ValueError as e:
        flash(str(e), 'error')
        return redirect(url_for('upload_page'))
    
    upload_results = []
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
            if not drive:
                flash('Google Drive not configured. Cannot create new client.', 'error')
                return redirect(url_for('upload_page'))
            
            try:
                folder = drive.CreateFile({
                    'title': client_name,
                    'parents': [{'id': ROOT_FOLDER_ID}],
                    'mimeType': 'application/vnd.google-apps.folder'
                })
                folder.Upload()
                folder_id = folder['id']
            except Exception as e:
                flash(f'Error creating folder: {str(e)}', 'error')
                return redirect(url_for('upload_page'))
            
            now = datetime.now() if USE_POSTGRESQL else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if USE_POSTGRESQL:
                cur.execute("INSERT INTO clients (name, folder_id, created_at, updated_at, created_by) VALUES (%s, %s, %s, %s, %s) RETURNING id",
                    (client_name, folder_id, now, now, session.get('user_id')))
                client_id = cur.fetchone()[0]
            else:
                cur.execute("INSERT INTO clients (name, folder_id, created_at, updated_at, created_by) VALUES (?, ?, ?, ?, ?)",
                    (client_name, folder_id, now, now, session.get('user_id')))
                client_id = cur.lastrowid
            conn.commit()
        else:
            client_id = client[0]
            folder_id = client[1]
        
        for doc_type in DOCUMENT_TYPES:
            file = request.files.get(doc_type)
            if file and file.filename:
                if not allowed_file(file.filename):
                    flash(f'{doc_type}: Invalid file format.', 'error')
                    continue
                if not validate_file_size(file):
                    flash(f'{doc_type}: File too large (max 10MB).', 'error')
                    continue
                
                try:
                    gfile = drive.CreateFile({
                        'title': f"{client_name}_{doc_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg",
                        'parents': [{'id': folder_id}]
                    })
                    gfile.SetContentFile(file)
                    gfile.Upload()
                    file_url = f"https://drive.google.com/uc?export=download&id={gfile['id']}"
                    
                    now = datetime.now() if USE_POSTGRESQL else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    if USE_POSTGRESQL:
                        cur.execute("""INSERT INTO documents (client_id, document_type, file_id, file_name, url, file_size, mime_type, upload_time, uploaded_by)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (client_id, document_type) DO UPDATE SET
                            file_id = EXCLUDED.file_id, file_name = EXCLUDED.file_name, url = EXCLUDED.url, upload_time = EXCLUDED.upload_time""",
                            (client_id, doc_type, gfile['id'], gfile['title'], file_url, file.content_length, file.content_type, now, session.get('user_id')))
                    else:
                        cur.execute("""INSERT OR REPLACE INTO documents (client_id, document_type, file_id, file_name, url, file_size, mime_type, upload_time, uploaded_by)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            (client_id, doc_type, gfile['id'], gfile['title'], file_url, file.content_length, file.content_type, now, session.get('user_id')))
                    
                    upload_results.append({'type': doc_type, 'filename': gfile['title'], 'url': file_url})
                except Exception as e:
                    flash(f'Error uploading {doc_type}: {str(e)}', 'error')
        
        now = datetime.now() if USE_POSTGRESQL else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if USE_POSTGRESQL:
            cur.execute("UPDATE clients SET updated_at = %s WHERE id = %s", (now, client_id))
        else:
            cur.execute("UPDATE clients SET updated_at = ? WHERE id = ?", (now, client_id))
        
        conn.commit()
        log_activity("DOCUMENT_UPLOADED", f"Uploaded {len(upload_results)} documents for {client_name}")
        flash(f'Successfully uploaded {len(upload_results)} document(s)!', 'success')
        return render_template('upload.html', success=True, name=client_name, upload_results=upload_results)
    except Exception as e:
        print(f"Upload error: {str(e)}")
        traceback.print_exc()
        flash(f'Upload error: {str(e)}', 'error')
        return redirect(url_for('upload_page'))
    finally:
        if cur:
            try: 
                cur.close()
            except: 
                pass
        if conn:
            try: 
                conn.close()
            except: 
                pass

@app.route('/fetch_data', methods=['POST'])
@login_required
def fetch_data():
    client_name = request.form.get('name', '').strip()
    if not client_name:
        flash('Client name is required.', 'error')
        return render_template('fetch.html')
    
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        if USE_POSTGRESQL:
            cur.execute("SELECT c.id, c.name, c.created_at, c.updated_at, c.folder_id FROM clients c WHERE c.name ILIKE %s", (f'%{client_name}%',))
        else:
            cur.execute("SELECT c.id, c.name, c.created_at, c.updated_at, c.folder_id FROM clients c WHERE c.name LIKE ?", (f'%{client_name}%',))
        
        client_row = cur.fetchone()
        if not client_row:
            return render_template('fetch.html', not_found=True, name=client_name)
        
        client_id = client_row[0]
        
        if USE_POSTGRESQL:
            cur.execute("SELECT document_type, file_id, file_name, url, file_size, upload_time FROM documents WHERE client_id = %s", (client_id,))
        else:
            cur.execute("SELECT document_type, file_id, file_name, url, file_size, upload_time FROM documents WHERE client_id = ?", (client_id,))
        
        docs = cur.fetchall()
        documents = {}
        
        for doc in docs:
            doc_type = doc[0]
            documents[doc_type] = {
                'file_id': doc[1], 
                'file_name': doc[2], 
                'url': doc[3],
                'file_size': doc[4] or 0, 
                'upload_time': doc[5], 
                'image_url': doc[3]
            }
        
        client = {
            'id': client_id, 
            'name': client_row[1],
            'created_at': client_row[2].strftime('%Y-%m-%d %H:%M:%S') if hasattr(client_row[2], 'strftime') else client_row[2],
            'updated_at': client_row[3].strftime('%Y-%m-%d %H:%M:%S') if hasattr(client_row[3], 'strftime') else client_row[3],
            'folder_id': client_row[4], 
            'documents': documents
        }
        
        log_activity("DOCUMENTS_VIEWED", f"Viewed documents for {client_row[1]}")
        return render_template('fetch.html', client=client)
    except Exception as e:
        print(f"Fetch data error: {str(e)}")
        traceback.print_exc()
        return render_template('fetch.html', error=str(e))
    finally:
        if cur:
            try: 
                cur.close()
            except: 
                pass
        if conn:
            try: 
                conn.close()
            except: 
                pass


@app.route('/download_document', methods=['POST'])
@login_required
def download_document():
    file_id = request.form.get('file_id', '')
    
    if not file_id:
        flash('File ID is required', 'error')
        return redirect(url_for('fetch_page'))
    
    if not drive:
        flash('Google Drive not configured', 'error')
        return redirect(url_for('fetch_page'))
    
    try:
        file = drive.CreateFile({'id': file_id})
        file.FetchMetadata()
        temp_path = os.path.join(UPLOAD_FOLDER, secure_filename(file['title']))
        file.GetContentFile(temp_path)
        log_activity("DOCUMENT_DOWNLOADED", f"Downloaded file: {file['title']}")
        
        response = send_file(temp_path, as_attachment=True, download_name=file['title'])
        
        @response.call_on_close
        def remove_file():
            cleanup_temp_file(temp_path)
        
        return response
    except Exception as e:
        print(f"Download error: {str(e)}")
        flash(f'Error downloading: {str(e)}', 'error')
        return redirect(url_for('fetch_page'))


@app.route('/delete_document', methods=['POST'])
@login_required
def delete_document():
    file_id = request.form.get('file_id', '')
    
    if not file_id:
        flash('File ID is required', 'error')
        return redirect(request.referrer or url_for('fetch_page'))
    
    if not drive:
        flash('Google Drive not configured', 'error')
        return redirect(request.referrer or url_for('fetch_page'))
    
    conn = None
    cur = None
    try:
        file = drive.CreateFile({'id': file_id})
        file.Delete()
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        if USE_POSTGRESQL:
            cur.execute("DELETE FROM documents WHERE file_id = %s", (file_id,))
        else:
            cur.execute("DELETE FROM documents WHERE file_id = ?", (file_id,))
        
        conn.commit()
        log_activity("DOCUMENT_DELETED", f"Deleted file: {file_id}")
        flash('Document deleted successfully', 'success')
        return redirect(request.referrer or url_for('fetch_page'))
    except Exception as e:
        print(f"Delete error: {str(e)}")
        flash(f'Error deleting document: {str(e)}', 'error')
        return redirect(request.referrer or url_for('fetch_page'))
    finally:
        if cur:
            try: 
                cur.close()
            except: 
                pass
        if conn:
            try: 
                conn.close()
            except: 
                pass


@app.route('/delete_client', methods=['POST'])
@login_required
def delete_client():
    client_name = request.form.get('name', '').strip()
    
    if not client_name:
        flash('Client name is required', 'error')
        return redirect(url_for('list_clients'))
    
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
            flash('Client not found', 'error')
            return redirect(url_for('list_clients'))
        
        client_id, folder_id = client[0], client[1]
        
        if drive and folder_id:
            try:
                folder = drive.CreateFile({'id': folder_id})
                folder.Delete()
            except: 
                pass
        
        if USE_POSTGRESQL:
            cur.execute("DELETE FROM clients WHERE id = %s", (client_id,))
        else:
            cur.execute("DELETE FROM clients WHERE id = ?", (client_id,))
        
        conn.commit()
        log_activity("CLIENT_DELETED", f"Deleted client: {client_name}")
        flash('Client and all documents deleted successfully', 'success')
        return redirect(url_for('list_clients'))
    except Exception as e:
        print(f"Delete client error: {str(e)}")
        flash(f'Error deleting client: {str(e)}', 'error')
        return redirect(url_for('list_clients'))
    finally:
        if cur:
            try: 
                cur.close()
            except: 
                pass
        if conn:
            try: 
                conn.close()
            except: 
                pass


@app.route('/edit_client/<int:client_id>', methods=['POST'])
@login_required
def edit_client(client_id):
    new_name = request.form.get('new_name', '').strip()
    
    if not new_name:
        return jsonify({'success': False, 'error': 'New name is required'})
    
    try:
        new_name = validate_and_sanitize_name(new_name)
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)})
    
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        if USE_POSTGRESQL:
            cur.execute("UPDATE clients SET name = %s WHERE id = %s", (new_name, client_id))
        else:
            cur.execute("UPDATE clients SET name = ? WHERE id = ?", (new_name, client_id))
        
        conn.commit()
        log_activity("CLIENT_RENAMED", f"Renamed client to: {new_name}")
        return jsonify({'success': True, 'message': 'Client name updated successfully'})
    except Exception as e:
        print(f"Edit client error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})
    finally:
        if cur:
            try: 
                cur.close()
            except: 
                pass
        if conn:
            try: 
                conn.close()
            except: 
                pass


@app.route('/manual-sync')
@login_required
def manual_sync():
    try:
        print("Starting manual Google Drive sync...")
        synced = sync_drive_to_database()
        flash(f'Synced {synced} documents from Google Drive', 'success')
        return redirect(url_for('list_clients'))
    except Exception as e:
        print(f"Sync error: {str(e)}")
        traceback.print_exc()
        flash(f'Error during sync: {str(e)}', 'error')
        return redirect(url_for('list_clients'))

# ============= API ROUTES =============

@app.route('/api/quick_search', methods=['GET'])
@login_required
def api_quick_search():
    query = request.args.get('q', '').strip()
    
    if len(query) < 2:
        return jsonify({'results': []})
    
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        if USE_POSTGRESQL:
            cur.execute("""SELECT c.name, c.updated_at, COUNT(d.id) as doc_count FROM clients c
                LEFT JOIN documents d ON c.id = d.client_id WHERE c.name ILIKE %s
                GROUP BY c.id, c.name, c.updated_at LIMIT 10""", (f'%{query}%',))
        else:
            cur.execute("""SELECT c.name, c.updated_at, COUNT(d.id) as doc_count FROM clients c
                LEFT JOIN documents d ON c.id = d.client_id WHERE c.name LIKE ?
                GROUP BY c.id, c.name LIMIT 10""", (f'%{query}%',))
        
        results = []
        for row in cur.fetchall():
            updated_at = row[1]
            if hasattr(updated_at, 'strftime'):
                updated_at = updated_at.strftime('%Y-%m-%d')
            elif updated_at:
                updated_at = str(updated_at)[:10]
            else:
                updated_at = ''
            results.append({'name': row[0], 'updated_at': updated_at, 'doc_count': row[2]})
        
        return jsonify({'results': results})
    except Exception as e:
        print(f"Quick search error: {str(e)}")
        return jsonify({'results': [], 'error': str(e)})
    finally:
        if cur:
            try: 
                cur.close()
            except: 
                pass
        if conn:
            try: 
                conn.close()
            except: 
                pass


@app.route('/api/client/<int:client_id>/documents', methods=['GET'])
@login_required
def get_client_documents(client_id):
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        if USE_POSTGRESQL:
            cur.execute("SELECT document_type, file_id, file_name, url, file_size, upload_time FROM documents WHERE client_id = %s", (client_id,))
        else:
            cur.execute("SELECT document_type, file_id, file_name, url, file_size, upload_time FROM documents WHERE client_id = ?", (client_id,))
        
        docs = cur.fetchall()
        documents = {}
        
        for doc in docs:
            doc_type = doc[0]
            documents[doc_type] = {
                'file_id': doc[1], 
                'file_name': doc[2], 
                'url': doc[3],
                'file_size': doc[4] or 0, 
                'upload_time': doc[5]
            }
        
        return jsonify({'success': True, 'documents': documents})
    except Exception as e:
        print(f"Get documents error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})
    finally:
        if cur:
            try: 
                cur.close()
            except: 
                pass
        if conn:
            try: 
                conn.close()
            except: 
                pass


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
            return jsonify({'success': False, 'error': 'Client not found'})
        
        folder_id = client[1]
        updated_docs = []
        
        for doc_type in DOCUMENT_TYPES:
            if request.form.get(f'delete_{doc_type}') == 'true':
                try:
                    if USE_POSTGRESQL:
                        cur.execute("SELECT file_id FROM documents WHERE client_id = %s AND document_type = %s", (client_id, doc_type))
                    else:
                        cur.execute("SELECT file_id FROM documents WHERE client_id = ? AND document_type = ?", (client_id, doc_type))
                    
                    doc_row = cur.fetchone()
                    if doc_row and drive:
                        try:
                            file = drive.CreateFile({'id': doc_row[0]})
                            file.Delete()
                        except: 
                            pass
                    
                    if USE_POSTGRESQL:
                        cur.execute("DELETE FROM documents WHERE client_id = %s AND document_type = %s", (client_id, doc_type))
                    else:
                        cur.execute("DELETE FROM documents WHERE client_id = ? AND document_type = ?", (client_id, doc_type))
                    conn.commit()
                    print(f"Deleted {doc_type} for client {client_id}")
                except Exception as e:
                    print(f"Error deleting {doc_type}: {str(e)}")
            
            file = request.files.get(doc_type)
            if file and file.filename:
                if not allowed_file(file.filename):
                    continue
                if not validate_file_size(file):
                    continue
                
                try:
                    if USE_POSTGRESQL:
                        cur.execute("SELECT file_id FROM documents WHERE client_id = %s AND document_type = %s", (client_id, doc_type))
                    else:
                        cur.execute("SELECT file_id FROM documents WHERE client_id = ? AND document_type = ?", (client_id, doc_type))
                    
                    old_doc = cur.fetchone()
                    if old_doc and drive:
                        try:
                            old_file = drive.CreateFile({'id': old_doc[0]})
                            old_file.Delete()
                        except: 
                            pass
                    
                    gfile = drive.CreateFile({
                        'title': f"{client_id}_{doc_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg",
                        'parents': [{'id': folder_id}]
                    })
                    gfile.SetContentFile(file)
                    gfile.Upload()
                    
                    file_url = f"https://drive.google.com/uc?export=download&id={gfile['id']}"
                    now = datetime.now() if USE_POSTGRESQL else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    
                    if USE_POSTGRESQL:
                        cur.execute("""INSERT INTO documents (client_id, document_type, file_id, file_name, url, file_size, mime_type, upload_time, uploaded_by)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (client_id, document_type) DO UPDATE SET
                            file_id = EXCLUDED.file_id, file_name = EXCLUDED.file_name, url = EXCLUDED.url, upload_time = EXCLUDED.upload_time""",
                            (client_id, doc_type, gfile['id'], gfile['title'], file_url, file.content_length, file.content_type, now, session.get('user_id')))
                    else:
                        cur.execute("""INSERT OR REPLACE INTO documents (client_id, document_type, file_id, file_name, url, file_size, mime_type, upload_time, uploaded_by)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            (client_id, doc_type, gfile['id'], gfile['title'], file_url, file.content_length, file.content_type, now, session.get('user_id')))
                    
                    conn.commit()
                    updated_docs.append(doc_type)
                    print(f"Updated {doc_type} for client {client_id}")
                except Exception as e:
                    print(f"Error uploading {doc_type}: {str(e)}")
        
        now = datetime.now() if USE_POSTGRESQL else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if USE_POSTGRESQL:
            cur.execute("UPDATE clients SET updated_at = %s WHERE id = %s", (now, client_id))
        else:
            cur.execute("UPDATE clients SET updated_at = ? WHERE id = ?", (now, client_id))
        
        conn.commit()
        log_activity("DOCUMENTS_UPDATED", f"Updated {len(updated_docs)} documents for client {client_id}")
        
        return jsonify({
            'success': True,
            'message': f'Successfully updated {len(updated_docs)} document(s)!',
            'updated': updated_docs
        })
    except Exception as e:
        print(f"Update documents error: {str(e)}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)})
    finally:
        if cur:
            try: 
                cur.close()
            except: 
                pass
        if conn:
            try: 
                conn.close()
            except: 
                pass


@app.route('/view-document/<path:file_url>')
@login_required
def view_document(file_url):
    try:
        return redirect(file_url)
    except Exception as e:
        print(f"View document error: {str(e)}")
        flash(f'Error viewing document: {str(e)}', 'error')
        return redirect(url_for('fetch_page'))


# ============= ADMIN ROUTES =============

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        
        if USE_POSTGRESQL:
            cur = conn.cursor(cursor_factory=DictCursor)
            cur.execute("SELECT id, username, email, role, created_at, failed_login_attempts, locked_until FROM users ORDER BY created_at DESC")
            users_raw = cur.fetchall()
            users = [tuple(user) for user in users_raw]
        else:
            cur = conn.cursor()
            cur.execute("SELECT id, username, email, role, created_at, failed_login_attempts, locked_until FROM users ORDER BY created_at DESC")
            users = cur.fetchall()
        
        if USE_POSTGRESQL:
            cur.execute("SELECT COUNT(*) FROM users WHERE role = %s", ('admin',))
            admin_count = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM users WHERE role = %s", ('user',))
            user_count = cur.fetchone()[0]
        else:
            cur.execute("SELECT COUNT(*) FROM users WHERE role = ?", ('admin',))
            admin_count = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM users WHERE role = ?", ('user',))
            user_count = cur.fetchone()[0]
        
        cur.execute("SELECT COUNT(*) FROM clients")
        clients_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM documents")
        docs_count = cur.fetchone()[0]
        
        stats = {
            'total_users': admin_count + user_count,
            'admin_users': admin_count,
            'regular_users': user_count,
            'total_clients': clients_count,
            'total_documents': docs_count
        }
        
        return render_template('admin_dashboard.html', users=users, stats=stats)
    except Exception as e:
        print(f"Admin dashboard error: {str(e)}")
        import traceback
        traceback.print_exc()
        flash('Error loading admin dashboard.', 'error')
        return redirect(url_for('dashboard'))
    finally:
        if cur:
            try: 
                cur.close()
            except: 
                pass
        if conn:
            try: 
                conn.close()
            except: 
                pass


@app.route('/admin/user/add', methods=['POST'])
@admin_required
def admin_add_user():
    """Admin can add new users"""
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '')
    role = request.form.get('role', 'user').strip()
    
    if not username or not email or not password:
        return jsonify({'success': False, 'error': 'All fields are required'})
    
    if len(username) < 3:
        return jsonify({'success': False, 'error': 'Username must be at least 3 characters'})
    
    if len(password) < 6:
        return jsonify({'success': False, 'error': 'Password must be at least 6 characters'})
    
    if role not in ['admin', 'user']:
        return jsonify({'success': False, 'error': 'Invalid role'})
    
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        hashed_password = generate_password_hash(password)
        now = datetime.now() if USE_POSTGRESQL else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if USE_POSTGRESQL:
            cur.execute("INSERT INTO users (username, password, email, role, created_at) VALUES (%s, %s, %s, %s, %s)",
                       (username, hashed_password, email, role, now))
        else:
            cur.execute("INSERT INTO users (username, password, email, role, created_at) VALUES (?, ?, ?, ?, ?)",
                       (username, hashed_password, email, role, now))
        
        conn.commit()
        log_activity("USER_CREATED", f"Admin created user: {username} ({role})")
        return jsonify({'success': True, 'message': f'User {username} created successfully'})
        
    except Exception as e:
        print(f"Add user error: {str(e)}")
        return jsonify({'success': False, 'error': 'Username or email already exists'})
    finally:
        if cur:
            try: 
                cur.close()
            except: 
                pass
        if conn:
            try: 
                conn.close()
            except: 
                pass


@app.route('/admin/user/<int:user_id>/role', methods=['POST'])
@admin_required
def change_user_role(user_id):
    """Admin can change user roles"""
    new_role = request.form.get('role', '').strip()
    
    if new_role not in ['user', 'admin']:
        return jsonify({'success': False, 'error': 'Invalid role'})
    
    if user_id == session.get('user_id') and new_role == 'user':
        return jsonify({'success': False, 'error': 'Cannot remove your own admin role'})
    
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
        log_activity("ROLE_CHANGED", f"User role changed to {new_role} for user ID: {user_id}")
        return jsonify({'success': True, 'message': f'User role changed to {new_role}'})
    except Exception as e:
        print(f"Change role error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})
    finally:
        if cur:
            try: 
                cur.close()
            except: 
                pass
        if conn:
            try: 
                conn.close()
            except: 
                pass


@app.route('/admin/user/<int:user_id>/password', methods=['POST'])
@admin_required
def admin_reset_password(user_id):
    """Admin can reset user passwords"""
    new_password = request.form.get('new_password', '')
    
    if not new_password or len(new_password) < 6:
        return jsonify({'success': False, 'error': 'Password must be at least 6 characters'})
    
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        hashed_password = generate_password_hash(new_password)
        
        if USE_POSTGRESQL:
            cur.execute("UPDATE users SET password = %s, failed_login_attempts = 0, locked_until = NULL WHERE id = %s",
                       (hashed_password, user_id))
            cur.execute("SELECT username FROM users WHERE id = %s", (user_id,))
        else:
            cur.execute("UPDATE users SET password = ?, failed_login_attempts = 0, locked_until = NULL WHERE id = ?",
                       (hashed_password, user_id))
            cur.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        
        user = cur.fetchone()
        username = user[0] if user else 'Unknown'
        
        conn.commit()
        log_activity("PASSWORD_RESET", f"Admin reset password for user: {username}")
        return jsonify({'success': True, 'message': f'Password reset for {username}'})
    except Exception as e:
        print(f"Reset password error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})
    finally:
        if cur:
            try: 
                cur.close()
            except: 
                pass
        if conn:
            try: 
                conn.close()
            except: 
                pass


@app.route('/admin/user/<int:user_id>/unlock', methods=['POST'])
@admin_required
def unlock_user(user_id):
    """Admin can unlock user accounts"""
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        if USE_POSTGRESQL:
            cur.execute("UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = %s", (user_id,))
        else:
            cur.execute("UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?", (user_id,))
        
        conn.commit()
        log_activity("USER_UNLOCKED", f"User ID {user_id} unlocked by admin")
        return jsonify({'success': True, 'message': 'User account unlocked'})
    except Exception as e:
        print(f"Unlock user error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})
    finally:
        if cur:
            try: 
                cur.close()
            except: 
                pass
        if conn:
            try: 
                conn.close()
            except: 
                pass


@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    """Admin can delete users"""
    if user_id == session.get('user_id'):
        return jsonify({'success': False, 'error': 'Cannot delete your own account'})
    
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
        username = user[0] if user else 'Unknown'
        
        if USE_POSTGRESQL:
            cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        else:
            cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
        
        conn.commit()
        log_activity("USER_DELETED", f"User deleted: {username}")
        return jsonify({'success': True, 'message': 'User account deleted'})
    except Exception as e:
        print(f"Delete user error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})
    finally:
        if cur:
            try: 
                cur.close()
            except: 
                pass
        if conn:
            try: 
                conn.close()
            except: 
                pass


@app.route('/admin/user/<int:user_id>/activity')
@admin_required
def user_activity(user_id):
    """Admin can view user activity logs"""
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
        username = user[0] if user else 'Unknown'
        
        if USE_POSTGRESQL:
            cur.execute("SELECT action, details, timestamp, ip_address FROM activity_logs WHERE user_id = %s ORDER BY timestamp DESC LIMIT 100", (user_id,))
        else:
            cur.execute("SELECT action, details, timestamp, ip_address FROM activity_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 100", (user_id,))
        
        activities = cur.fetchall()
        
        html = f'''<!DOCTYPE html>
<html><head><title>Activity Log - {username}</title>
<link rel="stylesheet" href="/static/style.css"></head>
<body><div class="container">
<h1>Activity Log: {username}</h1>
<a href="/admin/dashboard" class="link">Back to Admin</a>
<table style="width:100%; margin-top:20px; border-collapse:collapse;">
<tr style="background:#667eea; color:white;">
<th style="padding:10px; text-align:left;">Action</th>
<th style="padding:10px; text-align:left;">Details</th>
<th style="padding:10px; text-align:left;">Time</th>
<th style="padding:10px; text-align:left;">IP</th></tr>'''
        
        for act in activities:
            html += f'<tr style="border-bottom:1px solid #ddd;"><td style="padding:10px;">{act[0]}</td><td style="padding:10px;">{act[1] or "-"}</td><td style="padding:10px;">{act[2]}</td><td style="padding:10px;">{act[3] or "-"}</td></tr>'
        
        html += '</table></div></body></html>'
        return html
    except Exception as e:
        print(f"User activity error: {str(e)}")
        flash('Error loading activity logs.', 'error')
        return redirect(url_for('admin_dashboard'))
    finally:
        if cur:
            try: 
                cur.close()
            except: 
                pass
        if conn:
            try: 
                conn.close()
            except: 
                pass

@app.route('/api/user/role')
@login_required
def get_user_role():
    return jsonify({
        'role': session.get('role', 'user'),
        'username': session.get('username')
    })


@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(403)
def forbidden(e):
    return render_template('404.html'), 403

def sync_drive_to_database():
    if not drive:
        print("Google Drive not initialized")
        return 0
    
    conn = None
    cur = None
    try:
        print("Starting Google Drive sync...")
        synced_count = 0
        query = f"'{ROOT_FOLDER_ID}' in parents and trashed=false"
        folder_list = drive.ListFile({'q': query, 'maxResults': 1000}).GetList()
        print(f"Found {len(folder_list)} folders in Google Drive")
        
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
                        cur.execute("UPDATE clients SET folder_id = %s, updated_at = %s WHERE id = %s",
                            (folder_id, modified_date, client_id))
                    else:
                        cur.execute("UPDATE clients SET folder_id = ?, updated_at = ? WHERE id = ?",
                            (folder_id, modified_date, client_id))
                else:
                    if USE_POSTGRESQL:
                        cur.execute("INSERT INTO clients (name, folder_id, created_at, updated_at) VALUES (%s, %s, %s, %s) RETURNING id",
                            (folder_name, folder_id, created_date, modified_date))
                        client_id = cur.fetchone()[0]
                    else:
                        cur.execute("INSERT INTO clients (name, folder_id, created_at, updated_at) VALUES (?, ?, ?, ?)",
                            (folder_name, folder_id, created_date, modified_date))
                        client_id = cur.lastrowid
                    print(f"  Added: {folder_name}")
                
                files_query = f"'{folder_id}' in parents and trashed=false"
                try:
                    files_list = drive.ListFile({'q': files_query, 'maxResults': 1000}).GetList()
                except Exception as e:
                    print(f"  Skipping files for {folder_name}: {e}")
                    files_list = []
                
                for file in files_list:
                    try:
                        file_id = file['id']
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
                        
                        file_url = f"https://drive.google.com/uc?export=download&id={file_id}"
                        file_size = int(file.get('fileSize', 0))
                        mime_type = file.get('mimeType', 'application/octet-stream')
                        upload_time = file.get('createdDate', datetime.now().isoformat())[:19]
                        
                        if USE_POSTGRESQL:
                            cur.execute("""INSERT INTO documents (client_id, document_type, file_id, file_name, url, file_size, mime_type, upload_time)
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                                ON CONFLICT (client_id, document_type) DO UPDATE SET
                                file_id = EXCLUDED.file_id, file_name = EXCLUDED.file_name, url = EXCLUDED.url,
                                file_size = EXCLUDED.file_size, mime_type = EXCLUDED.mime_type, upload_time = EXCLUDED.upload_time""",
                                (client_id, doc_type, file_id, file['title'], file_url, file_size, mime_type, upload_time))
                            synced_count += 1
                        else:
                            try:
                                cur.execute("""INSERT INTO documents (client_id, document_type, file_id, file_name, url, file_size, mime_type, upload_time)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                                    (client_id, doc_type, file_id, file['title'], file_url, file_size, mime_type, upload_time))
                                synced_count += 1
                            except:
                                cur.execute("""UPDATE documents SET file_id = ?, file_name = ?, url = ?, file_size = ?, mime_type = ?, upload_time = ?
                                    WHERE client_id = ? AND document_type = ?""",
                                    (file_id, file['title'], file_url, file_size, mime_type, upload_time, client_id, doc_type))
                    except: 
                        continue
                conn.commit()
            except Exception as e:
                print(f"Error syncing {folder.get('title', '?')}: {e}")
                conn.rollback()
                continue
        
        print(f"Sync complete! {synced_count} documents synced")
        return synced_count
    except Exception as e:
        print(f"Sync error: {str(e)}")
        traceback.print_exc()
        return 0
    finally:
        if cur:
            try: 
                cur.close()
            except: 
                pass
        if conn:
            try: 
                conn.close()
            except: 
                pass


# ============= MAIN =============

if __name__ == '__main__':
    try:
        print("Starting initial sync on app startup...")
        synced = sync_drive_to_database()
        print(f"Sync complete: {synced} documents synced")
    except Exception as e:
        print(f"Sync warning: {e}")
    
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    port = int(os.getenv('PORT', 5000))
    app.run(debug=debug_mode, host='0.0.0.0', port=port)