from flask import Flask, render_template, request, Response, send_file, jsonify, redirect, url_for, session, flash
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive
import sqlite3
from datetime import datetime, timedelta
import os
import json
import tempfile
import traceback
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import secrets
import string
import re
import time
from googleapiclient.errors import HttpError

# ==================== INITIALIZATION ====================
load_dotenv()

app = Flask(__name__)

# CRITICAL FIX: Require SECRET_KEY to be set
SECRET_KEY = os.getenv('SECRET_KEY')
if not SECRET_KEY:
    print("❌ CRITICAL: SECRET_KEY environment variable not set!")
    print("Generate one with: python -c 'import secrets; print(secrets.token_hex(32))'")
    raise ValueError("SECRET_KEY must be set in environment variables for security!")
app.secret_key = SECRET_KEY

# Security Extensions
csrf = CSRFProtect(app)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Configuration
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'pdf'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
UPLOAD_FOLDER = 'uploads'
DOCUMENT_TYPES = ['datasheet', 'aadhaar', 'pan', 'bank_account']

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# FIXED: No hardcoded folder ID
ROOT_FOLDER_ID = os.getenv('GOOGLE_DRIVE_FOLDER_ID')
if not ROOT_FOLDER_ID:
    print("❌ CRITICAL: GOOGLE_DRIVE_FOLDER_ID not set!")
    raise ValueError("GOOGLE_DRIVE_FOLDER_ID must be set in environment variables!")
print(f"🔒 Using Google Drive Folder ID: {ROOT_FOLDER_ID}")

# ==================== VALIDATION HELPERS ====================
def validate_client_name(name):
    """Validate and sanitize client names"""
    if not name or not isinstance(name, str):
        raise ValueError("Client name is required")
    
    name = name.strip()
    
    if len(name) < 2:
        raise ValueError("Client name must be at least 2 characters")
    
    if len(name) > 100:
        raise ValueError("Client name is too long (max 100 characters)")
    
    # Allow alphanumeric, spaces, hyphens, underscores, dots
    if not re.match(r'^[a-zA-Z0-9\s\-_.]+$', name):
        raise ValueError("Client name contains invalid characters")
    
    return name

def escape_drive_query(text):
    """Escape special characters for Google Drive queries"""
    # Escape single quotes and backslashes
    return text.replace('\\', '\\\\').replace("'", "\\'")

# ==================== GOOGLE DRIVE SETUP ====================
def setup_google_auth():
    """Setup Google Drive authentication with proper error handling"""
    try:
        client_id = os.getenv('GOOGLE_CLIENT_ID')
        client_secret = os.getenv('GOOGLE_CLIENT_SECRET')
        refresh_token = os.getenv('GOOGLE_REFRESH_TOKEN')
        
        if not all([client_id, client_secret]):
            raise ValueError(
                "Missing Google OAuth credentials. "
                "Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env file"
            )
        
        client_config = {
            "installed": {
                "client_id": client_id,
                "client_secret": client_secret,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "redirect_uris": ["http://localhost"]
            }
        }
        
        client_secrets_file = 'client_secrets.json'
        with open(client_secrets_file, 'w') as f:
            json.dump(client_config, f)
        
        gauth = GoogleAuth(settings={
            'client_config_backend': 'file',
            'client_config_file': client_secrets_file,
            'save_credentials': False,
            'get_refresh_token': True,
        })
        
        if refresh_token:
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
            print("✅ Using existing refresh token")
        else:
            print("⚠️ First time setup - please authenticate with Google Drive")
            gauth.GetFlow()
            gauth.flow.params.clear()
            gauth.flow.params.update({
                'access_type': 'offline',
                'prompt': 'consent',
                'response_type': 'code'
            })
            gauth.LocalWebserverAuth()
            print(f"✅ Authentication complete. Save this refresh token: {gauth.credentials.refresh_token}")
        
        return gauth
    
    except Exception as e:
        print(f"❌ Error setting up Google Drive authentication: {str(e)}")
        traceback.print_exc()
        raise

try:
    gauth = setup_google_auth()
    drive = GoogleDrive(gauth)
    print("✅ Google Drive initialized successfully")
except Exception as e:
    print(f"❌ Failed to initialize Google Drive: {str(e)}")
    drive = None

# ==================== DATABASE SETUP ====================
def init_db():
    """Initialize database with proper error handling"""
    try:
        with sqlite3.connect("database.db") as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS users (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                username TEXT NOT NULL UNIQUE,
                                password TEXT NOT NULL,
                                email TEXT,
                                role TEXT DEFAULT 'user',
                                created_at TEXT NOT NULL,
                                failed_login_attempts INTEGER DEFAULT 0,
                                locked_until TEXT
                            )''')
            
            conn.execute('''CREATE TABLE IF NOT EXISTS clients (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                name TEXT NOT NULL UNIQUE,
                                folder_id TEXT NOT NULL UNIQUE,
                                created_at TEXT NOT NULL,
                                updated_at TEXT NOT NULL,
                                created_by INTEGER,
                                FOREIGN KEY (created_by) REFERENCES users (id)
                            )''')
            
            conn.execute('''CREATE TABLE IF NOT EXISTS documents (
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
                                UNIQUE(client_id, document_type)
                            )''')
            
            conn.execute('''CREATE TABLE IF NOT EXISTS activity_logs (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                user_id INTEGER,
                                action TEXT NOT NULL,
                                details TEXT,
                                timestamp TEXT NOT NULL,
                                ip_address TEXT,
                                FOREIGN KEY (user_id) REFERENCES users (id)
                            )''')
            
            # FIXED: Added missing indexes
            conn.execute('CREATE INDEX IF NOT EXISTS idx_client_name ON clients(name)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_folder_id ON clients(folder_id)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_client_id ON documents(client_id)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_doc_type ON documents(document_type)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_username ON users(username)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_activity_user ON activity_logs(user_id)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_activity_time ON activity_logs(timestamp)')
            
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users")
            if cursor.fetchone()[0] == 0:
                # FIXED: Generate strong password for default admin
                admin_password = secrets.token_urlsafe(16)
                hashed = generate_password_hash(admin_password)
                cursor.execute(
                    "INSERT INTO users (username, password, email, role, created_at) VALUES (?, ?, ?, ?, ?)",
                    ('admin', hashed, 'admin@example.com', 'admin', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                )
                print("✅ Default admin user created")
                print(f"🔑 Admin password: {admin_password}")
                print("⚠️ SAVE THIS PASSWORD AND CHANGE IT IMMEDIATELY!")
            
        print("✅ Database initialized successfully")
    except Exception as e:
        print(f"❌ Error initializing database: {str(e)}")
        raise

init_db()

# ==================== GOOGLE DRIVE SYNC FUNCTIONS ====================
def sync_drive_to_database():
    """Sync all clients and documents from Google Drive to database (FIXED version with duplicate handling)"""
    if not drive:
        print("⚠️ Google Drive not initialized, skipping sync")
        return 0

    try:
        print("🔄 Starting Google Drive sync...")
        synced_count = 0

        query = f"'{ROOT_FOLDER_ID}' in parents and trashed=false"
        print(f"🔍 Querying Google Drive with: {query}")
        
        try:
            folder_list = drive.ListFile({'q': query, 'maxResults': 50}).GetList()
        except Exception as e:
            print(f"⚠️ First Drive query failed: {e}")
            time.sleep(1)
            folder_list = drive.ListFile({'q': query, 'maxResults': 50}).GetList()

        print(f"📁 Found {len(folder_list)} folders/items in Google Drive")

        if len(folder_list) == 0:
            print("⚠️ No folders found! Possible reasons:")
            print("   - Wrong GOOGLE_DRIVE_FOLDER_ID")
            print("   - Folder empty or inaccessible")
            print("   - API permissions issue")
            return 0

        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()

            for folder in folder_list:
                try:
                    folder_name = folder['title']
                    folder_id = folder['id']
                    created_date = folder.get('createdDate', datetime.now().isoformat())[:19].replace('T', ' ')
                    modified_date = folder.get('modifiedDate', datetime.now().isoformat())[:19].replace('T', ' ')

                    cur.execute("SELECT id FROM clients WHERE name = ?", (folder_name,))
                    existing_client = cur.fetchone()

                    if existing_client:
                        client_id = existing_client[0]
                        cur.execute(
                            "UPDATE clients SET folder_id = ?, updated_at = ? WHERE id = ?",
                            (folder_id, modified_date, client_id)
                        )
                    else:
                        cur.execute(
                            "INSERT INTO clients (name, folder_id, created_at, updated_at) VALUES (?, ?, ?, ?)",
                            (folder_name, folder_id, created_date, modified_date)
                        )
                        client_id = cur.lastrowid
                        print(f"  ✅ Added new client: {folder_name}")

                    # FIXED: Better retry logic
                    files_query = f"'{folder_id}' in parents and trashed=false"
                    files_list = None
                    
                    for attempt in range(2):
                        try:
                            files_list = drive.ListFile({'q': files_query, 'maxResults': 50}).GetList()
                            break
                        except Exception as e:
                            if attempt == 1:  # Last attempt
                                print(f"❌ Failed to fetch files for {folder_name}: {e}")
                                files_list = []
                            else:
                                time.sleep(1)

                    for file in files_list:
                        try:
                            file_id = file['id']
                            file_name = file['title']
                            file_size = int(file.get('fileSize', 0))
                            mime_type = file.get('mimeType', 'application/octet-stream')
                            upload_time = file.get('createdDate', datetime.now().isoformat())[:19].replace('T', ' ')
                            file_url = f"https://drive.google.com/uc?export=download&id={file_id}"

                            file_lower = file_name.lower()
                            if 'datasheet' in file_lower:
                                doc_type = 'datasheet'
                            elif 'aadhaar' in file_lower or 'aadhar' in file_lower:
                                doc_type = 'aadhaar'
                            elif 'pan' in file_lower:
                                doc_type = 'pan'
                            elif 'bank' in file_lower or 'account' in file_lower:
                                doc_type = 'bank_account'
                            else:
                                doc_type = 'datasheet'

                            # FIXED: Check both file_id AND client_id + document_type
                            cur.execute("SELECT COUNT(*) FROM documents WHERE file_id = ?", (file_id,))
                            if cur.fetchone()[0] == 0:
                                # Check if document type already exists for this client
                                cur.execute(
                                    "SELECT file_id FROM documents WHERE client_id = ? AND document_type = ?",
                                    (client_id, doc_type)
                                )
                                existing_doc = cur.fetchone()
                                
                                if existing_doc:
                                    # Update existing document instead of inserting
                                    cur.execute(
                                        """UPDATE documents 
                                           SET file_id = ?, file_name = ?, url = ?, file_size = ?, 
                                               mime_type = ?, upload_time = ?
                                           WHERE client_id = ? AND document_type = ?""",
                                        (file_id, file_name, file_url, file_size, mime_type, 
                                         upload_time, client_id, doc_type)
                                    )
                                    print(f"  🔄 Updated: {folder_name} → {doc_type}")
                                else:
                                    # Insert new document
                                    cur.execute(
                                        """INSERT INTO documents 
                                           (client_id, document_type, file_id, file_name, url, file_size, mime_type, upload_time)
                                           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                                        (client_id, doc_type, file_id, file_name, file_url, file_size, mime_type, upload_time)
                                    )
                                    synced_count += 1
                                    print(f"  ✅ Synced: {folder_name} → {doc_type}")

                        except Exception as inner_e:
                            print(f"    ⚠️ Skipping file '{file.get('title', '?')}' in {folder_name}: {inner_e}")
                            continue

                    conn.commit()
                    time.sleep(0.5)  # Rate limiting

                except Exception as e:
                    print(f"  ❌ Error syncing folder '{folder.get('title', '?')}': {str(e)}")
                    continue

        print(f"✅ Sync complete! {synced_count} new documents added.")
        return synced_count

    except Exception as e:
        print(f"❌ Google Drive sync fatal error: {str(e)}")
        traceback.print_exc()
        return 0


def sync_single_client(client_name):
    """Sync a specific client folder from Google Drive (FIXED version)"""
    if not drive:
        return False

    try:
        # FIXED: Escape client name for query
        escaped_name = escape_drive_query(client_name)
        
        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()

            query = f"'{ROOT_FOLDER_ID}' in parents and title='{escaped_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
            
            try:
                folder_list = drive.ListFile({'q': query, 'maxResults': 10}).GetList()
            except Exception as e:
                print(f"⚠️ Initial folder fetch failed for {client_name}: {e}")
                time.sleep(1)
                folder_list = drive.ListFile({'q': query, 'maxResults': 10}).GetList()

            if not folder_list:
                print(f"⚠️ Client folder '{client_name}' not found on Drive.")
                return False

            folder = folder_list[0]
            folder_id = folder['id']

            cur.execute("SELECT id FROM clients WHERE name = ?", (client_name,))
            existing = cur.fetchone()

            if not existing:
                cur.execute(
                    "INSERT INTO clients (name, folder_id, created_at, updated_at) VALUES (?, ?, ?, ?)",
                    (client_name, folder_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                     datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                )

            client_id = existing[0] if existing else cur.lastrowid

            # FIXED: Better retry logic
            files_query = f"'{folder_id}' in parents and trashed=false"
            files_list = None
            
            for attempt in range(2):
                try:
                    files_list = drive.ListFile({'q': files_query, 'maxResults': 20}).GetList()
                    break
                except Exception as e:
                    if attempt == 1:
                        print(f"❌ Failed to fetch files: {e}")
                        return False
                    time.sleep(1)

            for file in files_list:
                try:
                    file_id = file['id']
                    cur.execute("SELECT COUNT(*) FROM documents WHERE file_id = ?", (file_id,))
                    if cur.fetchone()[0] == 0:
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
                            doc_type = 'datasheet'

                        cur.execute(
                            """INSERT INTO documents 
                               (client_id, document_type, file_id, file_name, url, file_size, mime_type, upload_time)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                            (client_id, doc_type, file_id, file['title'],
                             f"https://drive.google.com/uc?export=download&id={file_id}",
                             int(file.get('fileSize', 0)),
                             file.get('mimeType', 'application/octet-stream'),
                             file.get('createdDate', datetime.now().isoformat())[:19].replace('T', ' '))
                        )
                except Exception as e:
                    print(f"⚠️ Skipping file in {client_name}: {e}")
                    continue

            conn.commit()
        return True

    except Exception as e:
        print(f"❌ Error syncing single client '{client_name}': {str(e)}")
        return False

# ==================== HELPER FUNCTIONS ====================
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
    """FIXED: Include IP address for security"""
    try:
        user_id = session.get('user_id')
        ip_address = request.remote_addr
        with sqlite3.connect("database.db") as conn:
            conn.execute(
                "INSERT INTO activity_logs (user_id, action, details, timestamp, ip_address) VALUES (?, ?, ?, ?, ?)",
                (user_id, action, details, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip_address)
            )
    except Exception as e:
        print(f"Error logging activity: {str(e)}")

def get_or_create_client_folder(client_name):
    try:
        # FIXED: Validate client name first
        client_name = validate_client_name(client_name)
        
        if not drive:
            raise RuntimeError("Google Drive not initialized")
        
        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()
            cur.execute("SELECT folder_id FROM clients WHERE name = ?", (client_name,))
            result = cur.fetchone()
            
            if result:
                return result[0]
        
        folder_metadata = {
            'title': client_name,
            'mimeType': 'application/vnd.google-apps.folder',
            'parents': [{'id': ROOT_FOLDER_ID}]
        }
        folder = drive.CreateFile(folder_metadata)
        folder.Upload()
        folder.InsertPermission({'type': 'anyone', 'value': 'anyone', 'role': 'reader'})
        
        with sqlite3.connect("database.db") as conn:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            user_id = session.get('user_id')
            conn.execute(
                "INSERT INTO clients (name, folder_id, created_at, updated_at, created_by) VALUES (?, ?, ?, ?, ?)",
                (client_name, folder['id'], now, now, user_id)
            )
        
        log_activity("CREATE_CLIENT", f"Created client: {client_name}")
        print(f"✅ Created folder for client: {client_name}")
        return folder['id']
    
    except ValueError as e:
        print(f"❌ Validation error: {str(e)}")
        raise
    except Exception as e:
        print(f"❌ Error creating client folder: {str(e)}")
        raise RuntimeError(f"Failed to create client folder: {str(e)}")

def get_client_id(client_name):
    with sqlite3.connect("database.db") as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM clients WHERE name = ?", (client_name,))
        result = cur.fetchone()
        return result[0] if result else None

def cleanup_temp_file(filepath):
    """FIXED: More robust cleanup"""
    try:
        if filepath and os.path.exists(filepath):
            os.remove(filepath)
            return True
    except Exception as e:
        print(f"Warning: Could not remove temp file {filepath}: {str(e)}")
    return False

# ==================== LANDING PAGE ====================
@app.route('/')
def index():
    """Landing page - public access"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# FIXED: Add home route for compatibility
@app.route('/home')
def home():
    """Redirect to upload page"""
    if 'user_id' in session:
        return redirect(url_for('upload_page'))
    return redirect(url_for('index'))

# ==================== AUTHENTICATION ROUTES ====================
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # FIXED: Rate limiting
def login():
    """User login page with account lockout protection"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return render_template('login.html')
        
        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, username, password, role, failed_login_attempts, locked_until FROM users WHERE username = ?", (username,))
            user = cur.fetchone()
        
        if user:
            user_id, db_username, db_password, role, failed_attempts, locked_until = user
            
            # FIXED: Account lockout mechanism
            if locked_until:
                lock_time = datetime.strptime(locked_until, "%Y-%m-%d %H:%M:%S")
                if datetime.now() < lock_time:
                    remaining = (lock_time - datetime.now()).seconds // 60
                    flash(f'⚠️ Account locked. Try again in {remaining} minutes.', 'error')
                    log_activity("LOGIN_LOCKED", f"Locked account attempt: {username}")
                    return render_template('login.html')
                else:
                    # Unlock account
                    with sqlite3.connect("database.db") as conn:
                        conn.execute("UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?", (user_id,))
            
            if check_password_hash(db_password, password):
                # Successful login - reset failed attempts
                with sqlite3.connect("database.db") as conn:
                    conn.execute("UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?", (user_id,))
                
                session['user_id'] = user_id
                session['username'] = db_username
                session['role'] = role
                log_activity("LOGIN", f"User logged in: {username}")
                flash(f'Welcome back, {username}!', 'success')
                
                redirect_to = request.args.get('redirect', 'dashboard')
                if redirect_to == 'upload':
                    return redirect(url_for('upload_page'))
                elif redirect_to == 'search':
                    return redirect(url_for('fetch_page'))
                elif redirect_to == 'clients':
                    return redirect(url_for('list_clients'))
                else:
                    return redirect(url_for('dashboard'))
            else:
                # Failed login - increment counter
                failed_attempts += 1
                lock_time = None
                
                if failed_attempts >= 5:
                    lock_time = (datetime.now() + timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")
                    flash('⚠️ Too many failed attempts. Account locked for 15 minutes.', 'error')
                else:
                    flash(f'Invalid password. {5 - failed_attempts} attempts remaining.', 'error')
                
                with sqlite3.connect("database.db") as conn:
                    conn.execute("UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?", 
                               (failed_attempts, lock_time, user_id))
                
                log_activity("LOGIN_FAILED", f"Failed login attempt: {username}")
        else:
            flash('Invalid username or password.', 'error')
            log_activity("LOGIN_FAILED", f"Unknown username: {username}")
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per hour")  # FIXED: Rate limiting on registration
def register():
    """User registration page"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        email = request.form.get('email', '').strip()
        
        # FIXED: Better validation
        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('register.html')
        
        if not re.match(r'^[a-zA-Z0-9_-]{3,20}$', username):
            flash('Username must be 3-20 characters (letters, numbers, underscore, hyphen only).', 'error')
            return render_template('register.html')
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        
        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
            if cur.fetchone()[0] > 0:
                flash('Username already exists.', 'error')
                return render_template('register.html')
            
            hashed_password = generate_password_hash(password)
            cur.execute(
                "INSERT INTO users (username, password, email, role, created_at) VALUES (?, ?, ?, ?, ?)",
                (username, hashed_password, email, 'user', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            )
            conn.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    """User logout"""
    username = session.get('username')
    log_activity("LOGOUT", f"User logged out: {username}")
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
@limiter.limit("3 per hour")
def forgot_password():
    """Forgot password - FIXED with stronger reset codes"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        
        if not username:
            flash('Please enter your username.', 'error')
            return render_template('forgot_password.html')
        
        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()
            cur.execute("SELECT id FROM users WHERE username = ?", (username,))
            user = cur.fetchone()
        
        if user:
            # FIXED: Much stronger reset code (128 bits of entropy)
            reset_code = secrets.token_urlsafe(16)
            
            session['reset_username'] = username
            session['reset_code'] = reset_code
            session['reset_expiry'] = (datetime.now() + timedelta(minutes=15)).isoformat()
            
            log_activity("FORGOT_PASSWORD_INITIATED", f"Password reset requested for: {username}")
            
            return render_template('forgot_password.html', 
                                 reset_code=reset_code, 
                                 username=username)
        else:
            flash('Username not found.', 'error')
            log_activity("FORGOT_PASSWORD_FAILED", f"Unknown username: {username}")
    
    return render_template('forgot_password.html')

@app.route('/reset_password_confirm', methods=['POST'])
@csrf.exempt  # Handled in template
def reset_password_confirm():
    """Forgot password - Step 2: Confirm reset code and change password"""
    username = request.form.get('username', '').strip()
    reset_code = request.form.get('reset_code', '').strip()
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    # Verify session data
    if 'reset_username' not in session or 'reset_code' not in session:
        flash('Reset session expired. Please start again.', 'error')
        return redirect(url_for('forgot_password'))
    
    if username != session.get('reset_username'):
        flash('Invalid reset request.', 'error')
        return redirect(url_for('forgot_password'))
    
    # Check expiry
    expiry_time = datetime.fromisoformat(session.get('reset_expiry'))
    if datetime.now() > expiry_time:
        session.pop('reset_username', None)
        session.pop('reset_code', None)
        session.pop('reset_expiry', None)
        flash('Reset code expired. Please request a new one.', 'error')
        return redirect(url_for('forgot_password'))
    
    # FIXED: Use constant-time comparison to prevent timing attacks
    import hmac
    if not hmac.compare_digest(reset_code, session.get('reset_code')):
        flash('Invalid reset code. Please check and try again.', 'error')
        log_activity("RESET_PASSWORD_FAILED", f"Invalid code for: {username}")
        return render_template('forgot_password.html', 
                             reset_code=session.get('reset_code'),
                             username=username)
    
    # FIXED: Stronger password validation
    if len(new_password) < 8:
        flash('Password must be at least 8 characters long.', 'error')
        return render_template('forgot_password.html', 
                             reset_code=session.get('reset_code'),
                             username=username)
    
    if new_password != confirm_password:
        flash('Passwords do not match.', 'error')
        return render_template('forgot_password.html', 
                             reset_code=session.get('reset_code'),
                             username=username)
    
    # Update password
    with sqlite3.connect("database.db") as conn:
        cur = conn.cursor()
        hashed_password = generate_password_hash(new_password)
        cur.execute("UPDATE users SET password = ?, failed_login_attempts = 0, locked_until = NULL WHERE username = ?", 
                   (hashed_password, username))
        conn.commit()
    
    # Clear session
    session.pop('reset_username', None)
    session.pop('reset_code', None)
    session.pop('reset_expiry', None)
    
    log_activity("RESET_PASSWORD_SUCCESS", f"Password reset for: {username}")
    flash('Password reset successful! Please login with your new password.', 'success')
    return redirect(url_for('login'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change user password (when logged in)"""
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not current_password or not new_password or not confirm_password:
            flash('All fields are required.', 'error')
            return render_template('change_password.html')
        
        if len(new_password) < 8:
            flash('New password must be at least 8 characters long.', 'error')
            return render_template('change_password.html')
        
        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return render_template('change_password.html')
        
        if new_password == current_password:
            flash('New password must be different from current password.', 'error')
            return render_template('change_password.html')
        
        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()
            cur.execute("SELECT password FROM users WHERE id = ?", (session['user_id'],))
            user = cur.fetchone()
            
            if not user or not check_password_hash(user[0], current_password):
                flash('Current password is incorrect.', 'error')
                log_activity("PASSWORD_CHANGE_FAILED", "Incorrect current password")
                return render_template('change_password.html')
            
            hashed_password = generate_password_hash(new_password)
            cur.execute("UPDATE users SET password = ? WHERE id = ?", 
                       (hashed_password, session['user_id']))
            conn.commit()
        
        log_activity("PASSWORD_CHANGED", "Password updated successfully")
        flash('Password changed successfully! Please login again.', 'success')
        
        session.clear()
        return redirect(url_for('login'))
    
    return render_template('change_password.html')

# ==================== MAIN PAGES ====================
@app.route('/upload_page')
@login_required
def upload_page():
    """Upload page"""
    return render_template('upload.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard with statistics"""
    try:
        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()
            
            cur.execute("SELECT COUNT(*) FROM clients")
            total_clients = cur.fetchone()[0]
            
            cur.execute("SELECT COUNT(*) FROM documents")
            total_docs = cur.fetchone()[0]
            
            cur.execute("SELECT COUNT(*) FROM users")
            total_users = cur.fetchone()[0]
            
            # FIXED: Optimized query with JOIN
            cur.execute("""
                SELECT u.username, a.action, a.details, a.timestamp
                FROM activity_logs a
                LEFT JOIN users u ON a.user_id = u.id
                ORDER BY a.timestamp DESC
                LIMIT 10
            """)
            recent_activity = cur.fetchall()
            
            cur.execute("""
                SELECT document_type, COUNT(*) as count
                FROM documents
                GROUP BY document_type
                ORDER BY count DESC
            """)
            doc_distribution = cur.fetchall()
            
            cur.execute("""
                SELECT c.name, c.created_at, COUNT(d.id) as doc_count
                FROM clients c
                LEFT JOIN documents d ON c.id = d.client_id
                GROUP BY c.id
                ORDER BY c.created_at DESC
                LIMIT 5
            """)
            recent_clients = cur.fetchall()
        
        stats = {
            'total_clients': total_clients,
            'total_docs': total_docs,
            'total_users': total_users,
            'recent_activity': recent_activity,
            'doc_distribution': doc_distribution,
            'recent_clients': recent_clients
        }
        
        return render_template('dashboard.html', stats=stats)
    
    except Exception as e:
        print(f"Dashboard error: {str(e)}")
        traceback.print_exc()
        flash(f"Error loading dashboard: {str(e)}", "error")
        
        stats = {
            'total_clients': 0,
            'total_docs': 0,
            'total_users': 0,
            'recent_activity': [],
            'doc_distribution': [],
            'recent_clients': []
        }
        return render_template('dashboard.html', stats=stats)

# ==================== DOCUMENT UPLOAD ROUTES ====================
@app.route('/upload', methods=['POST'])
@login_required
@limiter.limit("10 per hour")  # FIXED: Rate limiting
def upload():
    """Upload documents for a client - FIXED with transaction safety"""
    if not drive:
        flash("Google Drive not initialized. Check server logs.", "error")
        return render_template('upload.html')
    
    try:
        name = request.form.get('name', '').strip()
        
        # FIXED: Validate client name
        try:
            name = validate_client_name(name)
        except ValueError as e:
            flash(str(e), "error")
            return render_template('upload.html')
        
        files = {
            'datasheet': request.files.get('datasheet'),
            'aadhaar': request.files.get('aadhaar'),
            'pan': request.files.get('pan'),
            'bank_account': request.files.get('bank_account')
        }
        
        has_files = any(file and file.filename != '' for file in files.values())
        if not has_files:
            flash("Please upload at least one document!", "error")
            return render_template('upload.html')
        
        uploaded_files = {}
        for doc_type, file in files.items():
            if file and file.filename != '':
                if not allowed_file(file.filename):
                    flash(f"Invalid file type for {doc_type}. Allowed: {', '.join(ALLOWED_EXTENSIONS)}", "error")
                    return render_template('upload.html')
                
                if not validate_file_size(file):
                    flash(f"{doc_type} file too large. Maximum: 10MB", "error")
                    return render_template('upload.html')
                
                uploaded_files[doc_type] = file
        
        folder_id = get_or_create_client_folder(name)
        client_id = get_client_id(name)
        user_id = session.get('user_id')
        
        # FIXED: Use transaction with proper locking
        with sqlite3.connect("database.db") as conn:
            conn.execute("BEGIN IMMEDIATE")  # Lock database
            
            try:
                cur = conn.cursor()
                for doc_type in uploaded_files.keys():
                    cur.execute(
                        "SELECT file_id FROM documents WHERE client_id = ? AND document_type = ?",
                        (client_id, doc_type)
                    )
                    old_file = cur.fetchone()
                    
                    if old_file:
                        try:
                            old_gfile = drive.CreateFile({'id': old_file[0]})
                            old_gfile.Delete()
                            log_activity("REPLACE_DOCUMENT", f"Replaced {doc_type} for {name}")
                        except Exception as e:
                            print(f"Warning: Could not delete old file: {str(e)}")
                        
                        conn.execute(
                            "DELETE FROM documents WHERE client_id = ? AND document_type = ?",
                            (client_id, doc_type)
                        )
                
                conn.commit()
            except Exception as e:
                conn.rollback()
                raise e
        
        upload_results = []
        temp_files = []  # Track temp files for cleanup
        
        for doc_type, file in uploaded_files.items():
            filename = secure_filename(file.filename)
            temp_path = os.path.join(UPLOAD_FOLDER, f"{secrets.token_hex(8)}_{filename}")
            temp_files.append(temp_path)
            
            try:
                file.save(temp_path)
                file_size = os.path.getsize(temp_path)
                
                gfile = drive.CreateFile({
                    'title': f"{name}_{doc_type}_{filename}",
                    'parents': [{'id': folder_id}]
                })
                gfile.SetContentFile(temp_path)
                gfile.Upload()
                gfile.content.close()
                
                gfile.InsertPermission({'type': 'anyone', 'value': 'anyone', 'role': 'reader'})
                
                gfile.FetchMetadata()
                file_url = f"https://drive.google.com/uc?export=download&id={gfile['id']}"
                mime_type = gfile.get('mimeType', 'image/jpeg')
                
                with sqlite3.connect("database.db") as conn:
                    conn.execute(
                        """INSERT INTO documents 
                           (client_id, document_type, file_id, file_name, url, file_size, mime_type, upload_time, uploaded_by) 
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (client_id, doc_type, gfile['id'], filename, file_url, 
                         file_size, mime_type, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user_id)
                    )
                
                upload_results.append({
                    'type': doc_type,
                    'filename': filename,
                    'url': file_url
                })
                
                log_activity("UPLOAD_DOCUMENT", f"Uploaded {doc_type} for {name}")
                
            except Exception as upload_error:
                raise upload_error
            finally:
                # Cleanup temp file
                cleanup_temp_file(temp_path)
        
        with sqlite3.connect("database.db") as conn:
            conn.execute(
                "UPDATE clients SET updated_at = ? WHERE name = ?",
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), name)
            )
        
        flash(f"Successfully processed {len(upload_results)} document(s) for {name}!", "success")
        return render_template("upload.html", success=True, name=name, upload_results=upload_results)
    
    except Exception as e:
        print(f"Upload error: {str(e)}")
        traceback.print_exc()
        flash(f"Upload failed: {str(e)}", "error")
        return render_template('upload.html')

# ==================== CLIENT SEARCH & FETCH ROUTES ====================
@app.route('/fetch')
@login_required
def fetch_page():
    """Fetch/search page"""
    return render_template('fetch.html')

@app.route('/fetch_data', methods=['POST'])
@login_required
def fetch_data():
    """Fetch client data and documents"""
    try:
        name = request.form.get('name', '').strip()
        
        if not name:
            flash("Please enter a name", "error")
            return render_template('fetch.html')
        
        # FIXED: Validate name
        try:
            name = validate_client_name(name)
        except ValueError as e:
            flash(str(e), "error")
            return render_template('fetch.html')
        
        sync_single_client(name)
        
        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()
            
            cur.execute("""
                SELECT c.id, c.name, c.folder_id, c.created_at, c.updated_at
                FROM clients c
                WHERE c.name = ?
            """, (name,))
            client = cur.fetchone()
            
            if not client:
                cur.execute("""
                    SELECT c.id, c.name, c.folder_id, c.created_at, c.updated_at
                    FROM clients c
                    WHERE LOWER(c.name) = LOWER(?)
                """, (name,))
                client = cur.fetchone()
            
            if not client:
                return render_template('fetch.html', not_found=True, name=name)
            
            client_id, client_name, folder_id, created_at, updated_at = client
            
            cur.execute("""
                SELECT document_type, file_id, file_name, url, file_size, mime_type, upload_time
                FROM documents
                WHERE client_id = ?
                ORDER BY 
                    CASE document_type
                        WHEN 'datasheet' THEN 1
                        WHEN 'aadhaar' THEN 2
                        WHEN 'pan' THEN 3
                        WHEN 'bank_account' THEN 4
                        ELSE 5
                    END
            """, (client_id,))
            
            documents = {}
            for row in cur.fetchall():
                doc_type, file_id, file_name, url, file_size, mime_type, upload_time = row
                documents[doc_type] = {
                    'file_id': file_id,
                    'file_name': file_name,
                    'url': url,
                    'file_size': file_size if file_size else 0,
                    'mime_type': mime_type if mime_type else 'application/octet-stream',
                    'upload_time': upload_time if upload_time else 'Unknown',
                    'image_url': f"/image/{file_id}"
                }
        
        client_info = {
            'id': client_id,
            'name': client_name,
            'folder_id': folder_id if folder_id else 'N/A',
            'created_at': created_at if created_at else 'Unknown',
            'updated_at': updated_at if updated_at else 'Unknown',
            'documents': documents
        }
        
        log_activity("VIEW_CLIENT", f"Viewed client: {client_name}")
        flash(f"Showing documents for: {client_name}", "success")
        return render_template('fetch.html', client=client_info, name=client_name)
    
    except Exception as e:
        print(f"Fetch error: {str(e)}")
        traceback.print_exc()
        flash(f"Error fetching data: {str(e)}", "error")
        return render_template('fetch.html')

# ==================== CLIENT MANAGEMENT ROUTES ====================
@app.route('/clients')
@login_required
def list_clients():
    """List all clients with sorting and filtering - FIXED"""
    try:
        sort_by = request.args.get('sort', 'updated_at')
        order = request.args.get('order', 'desc')
        filter_docs = request.args.get('filter_docs', '')
        search_query = request.args.get('search', '')
        
        valid_sorts = ['name', 'created_at', 'updated_at', 'doc_count']
        if sort_by not in valid_sorts:
            sort_by = 'updated_at'
        
        order = 'ASC' if order == 'asc' else 'DESC'
        
        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()
            
            query = """
                SELECT c.id, c.name, c.created_at, c.updated_at, COUNT(d.id) as doc_count
                FROM clients c
                LEFT JOIN documents d ON c.id = d.client_id
            """
            
            conditions = []
            params = []
            
            if search_query:
                conditions.append("c.name LIKE ?")
                params.append(f'%{search_query}%')
            
            if filter_docs:
                if filter_docs == '0':
                    conditions.append("(SELECT COUNT(*) FROM documents WHERE client_id = c.id) = 0")
                elif filter_docs == '1-3':
                    conditions.append("(SELECT COUNT(*) FROM documents WHERE client_id = c.id) BETWEEN 1 AND 3")
                elif filter_docs == '4':
                    conditions.append("(SELECT COUNT(*) FROM documents WHERE client_id = c.id) = 4")
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            
            query += " GROUP BY c.id"
            
            if sort_by == 'doc_count':
                query += f" ORDER BY doc_count {order}, c.updated_at DESC"
            else:
                query += f" ORDER BY c.{sort_by} {order}"
            
            cur.execute(query, params)
            clients = cur.fetchall()
        
        return render_template('clients.html', 
                             clients=clients, 
                             sort_by=sort_by.replace('_', ' ').title(),
                             order=order.lower(),
                             filter_docs=filter_docs,
                             search_query=search_query)
    
    except Exception as e:
        print(f"List clients error: {str(e)}")
        traceback.print_exc()
        flash(f"Error loading clients: {str(e)}", "error")
        # FIXED: Always return a response, even on error
        return render_template('clients.html', clients=[], error=str(e))
        
@app.route('/edit_client/<int:client_id>', methods=['POST'])
@login_required
def edit_client(client_id):
    """Edit client name"""
    try:
        new_name = request.form.get('new_name', '').strip()
        
        # FIXED: Validate new name
        try:
            new_name = validate_client_name(new_name)
        except ValueError as e:
            return jsonify({'success': False, 'error': str(e)})
        
        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()
            cur.execute("SELECT name FROM clients WHERE id = ?", (client_id,))
            result = cur.fetchone()
            
            if not result:
                return jsonify({'success': False, 'error': 'Client not found'})
            
            old_name = result[0]
            
            cur.execute("SELECT COUNT(*) FROM clients WHERE name = ? AND id != ?", (new_name, client_id))
            if cur.fetchone()[0] > 0:
                return jsonify({'success': False, 'error': 'Client name already exists'})
            
            cur.execute(
                "UPDATE clients SET name = ?, updated_at = ? WHERE id = ?",
                (new_name, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), client_id)
            )
            conn.commit()
        
        log_activity("EDIT_CLIENT", f"Renamed client from '{old_name}' to '{new_name}'")
        return jsonify({'success': True, 'message': f'Client renamed to {new_name}'})
    
    except Exception as e:
        print(f"Edit client error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/delete_client', methods=['POST'])
@login_required
@limiter.limit("5 per hour")  # FIXED: Rate limiting
def delete_client():
    """Delete entire client folder and all documents"""
    if not drive:
        return jsonify({'success': False, 'error': 'Google Drive not initialized'}), 503
    
    try:
        name = request.form.get('name', '').strip()
        
        # FIXED: Validate name
        try:
            name = validate_client_name(name)
        except ValueError as e:
            return jsonify({'success': False, 'error': str(e)}), 400
        
        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, folder_id FROM clients WHERE name = ?", (name,))
            result = cur.fetchone()
        
        if result:
            client_id, folder_id = result
            
            try:
                folder = drive.CreateFile({'id': folder_id})
                folder.Delete()
                
                with sqlite3.connect("database.db") as conn:
                    conn.execute("DELETE FROM documents WHERE client_id = ?", (client_id,))
                    conn.execute("DELETE FROM clients WHERE id = ?", (client_id,))
                
                log_activity("DELETE_CLIENT", f"Deleted client and all documents: {name}")
                return jsonify({'success': True, 'message': f'Successfully deleted all data for {name}'})
            
            except Exception as e:
                return jsonify({'success': False, 'error': f'Failed to delete: {str(e)}'}), 500
        else:
            return jsonify({'success': False, 'error': 'Client not found'}), 404
    
    except Exception as e:
        print(f"Delete error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ==================== DOCUMENT MANAGEMENT ROUTES ====================
@app.route('/image/<file_id>')
@login_required
def serve_image(file_id):
    """Serve image from Google Drive - FIXED memory handling"""
    if not drive:
        return "Google Drive not initialized", 503
    
    temp_path = None
    try:
        gfile = drive.CreateFile({'id': file_id})
        gfile.FetchMetadata()
        
        # FIXED: Use send_file directly, cleanup in finally
        temp_path = tempfile.mktemp(suffix='.tmp')
        gfile.GetContentFile(temp_path)
        
        mime_type = gfile.get('mimeType', 'image/jpeg')
        
        return send_file(
            temp_path,
            mimetype=mime_type,
            as_attachment=False,
            download_name=gfile.get('title', 'image')
        )
    
    except Exception as e:
        print(f"Error serving image: {str(e)}")
        traceback.print_exc()
        return f"Error loading image: {str(e)}", 404
    
    finally:
        # FIXED: Always cleanup
        if temp_path:
            cleanup_temp_file(temp_path)

@app.route('/download_document', methods=['POST'])
@login_required
def download_document():
    """Download a specific document"""
    if not drive:
        return "Google Drive not initialized", 503
    
    try:
        file_id = request.form.get('file_id', '').strip()
        
        if not file_id:
            return "File ID required", 400
        
        gfile = drive.CreateFile({'id': file_id})
        gfile.FetchMetadata()
        
        mime_type = gfile.get('mimeType', 'image/jpeg')
        if 'png' in mime_type:
            suffix = '.png'
        elif 'jpeg' in mime_type or 'jpg' in mime_type:
            suffix = '.jpg'
        elif 'pdf' in mime_type:
            suffix = '.pdf'
        else:
            suffix = '.jpg'
        
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
            temp_path = temp_file.name
        
        gfile.GetContentFile(temp_path)
        
        filename = gfile.get('title', 'document')
        log_activity("DOWNLOAD_DOCUMENT", f"Downloaded file: {filename}")
        
        return send_file(
            temp_path,
            as_attachment=True,
            download_name=filename,
            mimetype=mime_type
        )
    
    except Exception as e:
        print(f"Download error: {str(e)}")
        return f"Download failed: {str(e)}", 500

@app.route('/delete_document', methods=['POST'])
@login_required
def delete_document():
    """Delete a specific document"""
    if not drive:
        return jsonify({'success': False, 'error': 'Google Drive not initialized'}), 503
    
    try:
        file_id = request.form.get('file_id', '').strip()
        
        if not file_id:
            return jsonify({'success': False, 'error': 'File ID required'}), 400
        
        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()
            cur.execute("SELECT document_type, client_id FROM documents WHERE file_id = ?", (file_id,))
            result = cur.fetchone()
            
            if not result:
                return jsonify({'success': False, 'error': 'Document not found'}), 404
            
            doc_type, client_id = result
        
        try:
            gfile = drive.CreateFile({'id': file_id})
            gfile.Delete()
        except Exception as e:
            print(f"Warning: Could not delete from Drive: {str(e)}")
        
        with sqlite3.connect("database.db") as conn:
            conn.execute("DELETE FROM documents WHERE file_id = ?", (file_id,))
        
        log_activity("DELETE_DOCUMENT", f"Deleted {doc_type} document")
        return jsonify({'success': True, 'message': f'Successfully deleted {doc_type}'})
    
    except Exception as e:
        print(f"Delete document error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ==================== API ROUTES ====================
@app.route('/api/quick_search')
@login_required
def quick_search():
    """Quick search API endpoint"""
    try:
        query = request.args.get('q', '').strip()
        
        if not query or len(query) < 2:
            return jsonify({'results': []})
        
        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT c.name, COUNT(d.id) as doc_count, c.updated_at
                FROM clients c
                LEFT JOIN documents d ON c.id = d.client_id
                WHERE c.name LIKE ?
                GROUP BY c.id
                ORDER BY c.updated_at DESC
                LIMIT 10
            """, (f'%{query}%',))
            
            results = []
            for row in cur.fetchall():
                results.append({
                    'name': row[0],
                    'doc_count': row[1],
                    'updated_at': row[2][:10] if row[2] else ''
                })
        
        return jsonify({'results': results})
    
    except Exception as e:
        print(f"Quick search error: {str(e)}")
        return jsonify({'results': [], 'error': str(e)})

# ==================== ERROR HANDLERS ====================
@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors"""
    flash("Internal server error. Please try again.", "error")
    return redirect(url_for('index')), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limiting"""
    return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429

# ==================== APPLICATION STARTUP ====================
if __name__ == '__main__':
    # Only run sync on main process (not reloader)
    if os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        print("\n" + "=" * 60)
        print("🚀 LIC Manager Starting Up")
        print("=" * 60)
        
        try:
            print("🔄 Running initial Google Drive sync...")
            synced = sync_drive_to_database()
            if synced > 0:
                print(f"✅ Initial sync complete! Synced {synced} new documents")
            else:
                print(f"✅ Sync complete! All documents already in database")
        except Exception as e:
            print(f"⚠️ Sync warning (non-critical): {e}")
        
        print("=" * 60)
        print("✅ Server ready!")
        print("=" * 60 + "\n")
    
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0', port=int(os.getenv('PORT', 5000)))