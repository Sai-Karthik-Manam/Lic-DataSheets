from flask import Flask, render_template, request, Response, send_file, jsonify, redirect, url_for, session, flash
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive
from psycopg2.extras import DictCursor
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
from datetime import datetime, timedelta
from googleapiclient.errors import HttpError

# ==================== INITIALIZATION ====================
load_dotenv()

app = Flask(__name__)

# CRITICAL: Require SECRET_KEY to be set
SECRET_KEY = os.getenv('SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("SECRET_KEY must be set in environment variables!")
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
UPLOAD_FOLDER = tempfile.gettempdir()
DOCUMENT_TYPES = ['datasheet', 'aadhaar', 'pan', 'bank_account']

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Google Drive Configuration
ROOT_FOLDER_ID = os.getenv('GOOGLE_DRIVE_FOLDER_ID')
if not ROOT_FOLDER_ID:
    raise ValueError("GOOGLE_DRIVE_FOLDER_ID must be set in environment variables!")

# ==================== DATABASE DETECTION ====================
USE_POSTGRESQL = os.getenv('DB_HOST') is not None

if USE_POSTGRESQL:
    print("Using PostgreSQL database")
    import psycopg2
    from psycopg2.extras import DictCursor
    
    def get_db_connection():
        conn = psycopg2.connect(
            host=os.getenv('DB_HOST'),
            database=os.getenv('DB_NAME'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            port=os.getenv('DB_PORT', 5432)
        )
        return conn
else:
    print("Using SQLite database")
    import sqlite3
    
    def get_db_connection():
        conn = sqlite3.connect("database.db")
        conn.row_factory = sqlite3.Row
        return conn

# ==================== DATABASE INITIALIZATION ====================
def init_db():
    """Initialize database with tables (works for both SQLite and PostgreSQL)"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        if USE_POSTGRESQL:
            # PostgreSQL syntax
            cur.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    email VARCHAR(255),
                    role VARCHAR(50) DEFAULT 'user',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    failed_login_attempts INTEGER DEFAULT 0,
                    locked_until TIMESTAMP
                )
            ''')
            
            cur.execute('''
                CREATE TABLE IF NOT EXISTS clients (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(255) UNIQUE NOT NULL,
                    folder_id VARCHAR(255) UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_by INTEGER REFERENCES users(id)
                )
            ''')
            
            cur.execute('''
                CREATE TABLE IF NOT EXISTS documents (
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
                    UNIQUE(client_id, document_type)
                )
            ''')
            
            cur.execute('''
                CREATE TABLE IF NOT EXISTS activity_logs (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id),
                    action VARCHAR(255) NOT NULL,
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ip_address VARCHAR(50)
                )
            ''')
            
            # Create indexes
            cur.execute('CREATE INDEX IF NOT EXISTS idx_client_name ON clients(name)')
            cur.execute('CREATE INDEX IF NOT EXISTS idx_folder_id ON clients(folder_id)')
            cur.execute('CREATE INDEX IF NOT EXISTS idx_client_id ON documents(client_id)')
            cur.execute('CREATE INDEX IF NOT EXISTS idx_doc_type ON documents(document_type)')
            cur.execute('CREATE INDEX IF NOT EXISTS idx_username ON users(username)')
            
        else:
            # SQLite syntax
            cur.execute('''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                email TEXT,
                role TEXT DEFAULT 'user',
                created_at TEXT NOT NULL,
                failed_login_attempts INTEGER DEFAULT 0,
                locked_until TEXT
            )''')
            
            cur.execute('''CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                folder_id TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                created_by INTEGER,
                FOREIGN KEY (created_by) REFERENCES users (id)
            )''')
            
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
                UNIQUE(client_id, document_type)
            )''')
            
            cur.execute('''CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                details TEXT,
                timestamp TEXT NOT NULL,
                ip_address TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )''')
            
            # Create indexes
            cur.execute('CREATE INDEX IF NOT EXISTS idx_client_name ON clients(name)')
            cur.execute('CREATE INDEX IF NOT EXISTS idx_folder_id ON clients(folder_id)')
            cur.execute('CREATE INDEX IF NOT EXISTS idx_client_id ON documents(client_id)')
            cur.execute('CREATE INDEX IF NOT EXISTS idx_doc_type ON documents(document_type)')
            cur.execute('CREATE INDEX IF NOT EXISTS idx_username ON users(username)')
        
        # Check if admin exists
        if USE_POSTGRESQL:
            cur.execute("SELECT COUNT(*) FROM users WHERE username = %s", ('admin',))
        else:
            cur.execute("SELECT COUNT(*) FROM users WHERE username = ?", ('admin',))
        
        if cur.fetchone()[0] == 0:
            admin_password = secrets.token_urlsafe(16)
            hashed = generate_password_hash(admin_password)
            
            if USE_POSTGRESQL:
                cur.execute(
                    "INSERT INTO users (username, password, email, role, created_at) VALUES (%s, %s, %s, %s, %s)",
                    ('admin', hashed, 'admin@example.com', 'admin', datetime.now())
                )
            else:
                cur.execute(
                    "INSERT INTO users (username, password, email, role, created_at) VALUES (?, ?, ?, ?, ?)",
                    ('admin', hashed, 'admin@example.com', 'admin', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                )
            
            print("Admin user created")
            print(f"Admin password: {admin_password}")
            print("SAVE THIS PASSWORD AND CHANGE IT IMMEDIATELY!")
        
        conn.commit()
        cur.close()
        conn.close()
        print("Database initialized successfully")
    except Exception as e:
        print(f"Database initialization error: {str(e)}")
        traceback.print_exc()
        raise

try:
    init_db()
except Exception as e:
    print(f"⚠️ Database initialization warning (non-fatal): {e}")
    print("The app will attempt to initialize on first request")
# ==================== GOOGLE DRIVE SETUP ====================
def setup_google_auth():
    """Setup Google Drive authentication"""
    try:
        client_id = os.getenv('GOOGLE_CLIENT_ID')
        client_secret = os.getenv('GOOGLE_CLIENT_SECRET')
        refresh_token = os.getenv('GOOGLE_REFRESH_TOKEN')
        
        if not all([client_id, client_secret, refresh_token]):
            print("Warning: Google Drive credentials not configured")
            return None
        
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
        
        client_secrets_file = os.path.join(tempfile.gettempdir(), 'client_secrets.json')
        with open(client_secrets_file, 'w') as f:
            json.dump(client_config, f)
        
        gauth = GoogleAuth(settings={
            'client_config_backend': 'file',
            'client_config_file': client_secrets_file,
            'save_credentials': False,
            'get_refresh_token': False,
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

def sync_drive_to_database():
    """Sync all clients and documents from Google Drive to database - OPTIMIZED"""
    if not drive:
        print("Google Drive not initialized")
        return 0

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
                        cur.execute(
                            "UPDATE clients SET folder_id = %s, updated_at = %s WHERE id = %s",
                            (folder_id, modified_date, client_id)
                        )
                    else:
                        cur.execute(
                            "UPDATE clients SET folder_id = ?, updated_at = ? WHERE id = ?",
                            (folder_id, modified_date, client_id)
                        )
                else:
                    if USE_POSTGRESQL:
                        cur.execute(
                            "INSERT INTO clients (name, folder_id, created_at, updated_at) VALUES (%s, %s, %s, %s) RETURNING id",
                            (folder_name, folder_id, created_date, modified_date)
                        )
                        client_id = cur.fetchone()[0]
                    else:
                        cur.execute(
                            "INSERT INTO clients (name, folder_id, created_at, updated_at) VALUES (?, ?, ?, ?)",
                            (folder_name, folder_id, created_date, modified_date)
                        )
                        client_id = cur.lastrowid
                    
                    print(f"  Added: {folder_name}")
                
                # Sync files in folder
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
                        
                        # Determine document type
                        if 'datasheet' in file_lower:
                            doc_type = 'datasheet'
                        elif 'aadhaar' in file_lower or 'aadhar' in file_lower:
                            doc_type = 'aadhaar'
                        elif 'pan' in file_lower:
                            doc_type = 'pan'
                        elif 'bank' in file_lower or 'account' in file_lower:
                            doc_type = 'bank_account'
                        else:
                            continue  # Skip uncategorized files
                        
                        file_url = f"https://drive.google.com/uc?export=download&id={file_id}"
                        file_size = int(file.get('fileSize', 0))
                        mime_type = file.get('mimeType', 'application/octet-stream')
                        upload_time = file.get('createdDate', datetime.now().isoformat())[:19]
                        
                        # Use UPSERT to handle duplicates
                        if USE_POSTGRESQL:
                            cur.execute("""
                                INSERT INTO documents 
                                (client_id, document_type, file_id, file_name, url, file_size, mime_type, upload_time)
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                                ON CONFLICT (client_id, document_type) 
                                DO UPDATE SET 
                                    file_id = EXCLUDED.file_id,
                                    file_name = EXCLUDED.file_name,
                                    url = EXCLUDED.url,
                                    file_size = EXCLUDED.file_size,
                                    mime_type = EXCLUDED.mime_type,
                                    upload_time = EXCLUDED.upload_time
                            """, (client_id, doc_type, file_id, file['title'], file_url, file_size, mime_type, upload_time))
                            synced_count += 1
                        else:
                            # SQLite: try insert, ignore if duplicate
                            try:
                                cur.execute(
                                    """INSERT INTO documents 
                                       (client_id, document_type, file_id, file_name, url, file_size, mime_type, upload_time)
                                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                                    (client_id, doc_type, file_id, file['title'], file_url, file_size, mime_type, upload_time)
                                )
                                synced_count += 1
                            except:
                                # Update if duplicate
                                cur.execute(
                                    """UPDATE documents 
                                       SET file_id = ?, file_name = ?, url = ?, file_size = ?, mime_type = ?, upload_time = ?
                                       WHERE client_id = ? AND document_type = ?""",
                                    (file_id, file['title'], file_url, file_size, mime_type, upload_time, client_id, doc_type)
                                )
                    
                    except Exception as e:
                        continue
                
                # REMOVED time.sleep(0.5) - this was causing timeouts
                conn.commit()
                
            except Exception as e:
                print(f"Error syncing {folder.get('title', '?')}: {e}")
                conn.rollback()
                continue
        
        cur.close()
        conn.close()
        print(f"✅ Sync complete! {synced_count} documents synced")
        return synced_count
    
    except Exception as e:
        print(f"❌ Sync error: {str(e)}")
        traceback.print_exc()
        return 0
# ==================== VALIDATION HELPERS ====================
def validate_client_name(name):
    """Validate client names"""
    if not name or not isinstance(name, str):
        raise ValueError("Client name is required")
    
    name = name.strip()
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
            flash('Please login to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def log_activity(action, details=""):
    """Log user activity"""
    try:
        user_id = session.get('user_id')
        ip_address = request.remote_addr
        conn = get_db_connection()
        cur = conn.cursor()
        
        if USE_POSTGRESQL:
            cur.execute(
                "INSERT INTO activity_logs (user_id, action, details, timestamp, ip_address) VALUES (%s, %s, %s, %s, %s)",
                (user_id, action, details, datetime.now(), ip_address)
            )
        else:
            cur.execute(
                "INSERT INTO activity_logs (user_id, action, details, timestamp, ip_address) VALUES (?, ?, ?, ?, ?)",
                (user_id, action, details, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip_address)
            )
        
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Error logging activity: {str(e)}")

def cleanup_temp_file(filepath):
    try:
        if filepath and os.path.exists(filepath):
            os.remove(filepath)
            return True
    except Exception as e:
        print(f"Warning: Could not remove temp file: {str(e)}")
    return False

# ==================== BASIC ROUTES ====================
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return render_template('login.html')
        
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            if USE_POSTGRESQL:
                from psycopg2.extras import DictCursor
                cur = conn.cursor(cursor_factory=DictCursor)
                cur.execute(
                    "SELECT id, username, password, role, failed_login_attempts, locked_until FROM users WHERE username = %s",
                    (username,)
                )
                user_row = cur.fetchone()
                user_dict = dict(user_row) if user_row else None
            else:
                cur.execute(
                    "SELECT id, username, password, role, failed_login_attempts, locked_until FROM users WHERE username = ?",
                    (username,)
                )
                user_row = cur.fetchone()
                user_dict = {
                    'id': user_row[0], 'username': user_row[1], 'password': user_row[2],
                    'role': user_row[3], 'failed_login_attempts': user_row[4], 'locked_until': user_row[5]
                } if user_row else None
            
            if user_dict:
                # Check if account is locked
                if user_dict['locked_until']:
                    try:
                        if USE_POSTGRESQL:
                            lock_time = user_dict['locked_until']
                        else:
                            lock_time = datetime.strptime(str(user_dict['locked_until']), "%Y-%m-%d %H:%M:%S")
                        
                        if lock_time and lock_time > datetime.now():
                            flash('Account locked. Try again later.', 'error')
                            cur.close()
                            conn.close()
                            return render_template('login.html')
                    except Exception as e:
                        print(f"Lock check error: {e}")
                
                # Check password
                if check_password_hash(user_dict['password'], password):
                    # Successful login
                    session['user_id'] = user_dict['id']
                    session['username'] = user_dict['username']
                    session['role'] = user_dict['role']
                    
                    # Reset failed attempts
                    if USE_POSTGRESQL:
                        cur.execute("UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = %s", (user_dict['id'],))
                    else:
                        cur.execute("UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?", (user_dict['id'],))
                    
                    conn.commit()
                    cur.close()
                    conn.close()
                    
                    log_activity("LOGIN", f"User logged in: {username}")
                    flash(f'Welcome back, {username}!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    # Failed password - increment counter
                    failed_attempts = user_dict['failed_login_attempts'] + 1
                    lock_time = None
                    
                    if failed_attempts >= 5:
                        lock_time = datetime.now() + timedelta(minutes=15)
                        flash('Too many failed attempts. Account locked for 15 minutes.', 'error')
                    else:
                        flash(f'Invalid password. {5 - failed_attempts} attempts remaining.', 'error')
                    
                    if USE_POSTGRESQL:
                        cur.execute("UPDATE users SET failed_login_attempts = %s, locked_until = %s WHERE id = %s",
                                   (failed_attempts, lock_time, user_dict['id']))
                    else:
                        cur.execute("UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?",
                                   (failed_attempts, lock_time.strftime("%Y-%m-%d %H:%M:%S") if lock_time else None, user_dict['id']))
                    
                    conn.commit()
            else:
                flash('Invalid username or password.', 'error')
            
            cur.close()
            conn.close()
        except Exception as e:
            print(f"Login error: {str(e)}")
            traceback.print_exc()
            flash('An error occurred. Please try again.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    username = session.get('username')
    log_activity("LOGOUT", f"User logged out: {username}")
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        if USE_POSTGRESQL:
            cur.execute("SELECT COUNT(*) as count FROM clients")
            total_clients = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) as count FROM documents")
            total_docs = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) as count FROM users")
            total_users = cur.fetchone()[0]
        else:
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
        
        cur.close()
        conn.close()
        return render_template('dashboard.html', stats=stats)
    except Exception as e:
        print(f"Dashboard error: {str(e)}")
        flash(f"Error loading dashboard: {str(e)}", "error")
        return render_template('dashboard.html', stats={})

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
    """List clients - shows 20 most recent by default, all results if searching"""
    try:
        sort_by = request.args.get('sort', 'updated_at')
        order = request.args.get('order', 'desc')
        search_query = request.args.get('search', '').strip()
        
        order = 'ASC' if order == 'asc' else 'DESC'
        valid_sorts = ['name', 'created_at', 'updated_at']
        
        if sort_by not in valid_sorts:
            sort_by = 'updated_at'
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Base query
        base_query = """
            SELECT c.id, c.name, c.created_at, c.updated_at, COUNT(d.id) as doc_count
            FROM clients c
            LEFT JOIN documents d ON c.id = d.client_id
        """
        
        # If searching, show all matching results
        # If not searching, limit to 20 most recent
        if search_query:
            if USE_POSTGRESQL:
                query = base_query + " WHERE c.name ILIKE %s GROUP BY c.id ORDER BY c." + sort_by + " " + order
                cur.execute(query, (f'%{search_query}%',))
            else:
                query = base_query + " WHERE c.name LIKE ? GROUP BY c.id ORDER BY c." + sort_by + " " + order
                cur.execute(query, (f'%{search_query}%',))
        else:
            # No search: show 20 most recent (ordered by updated_at DESC)
            if USE_POSTGRESQL:
                query = base_query + " GROUP BY c.id ORDER BY c.updated_at DESC LIMIT 20"
                cur.execute(query)
            else:
                query = base_query + " GROUP BY c.id ORDER BY c.updated_at DESC LIMIT 20"
                cur.execute(query)
        
        clients = cur.fetchall()
        cur.close()
        conn.close()
        
        # Convert to list of tuples for template
        if USE_POSTGRESQL:
            clients_list = [tuple(client) for client in clients]
        else:
            clients_list = clients
        
        return render_template('clients.html', 
                             clients=clients_list, 
                             sort_by=sort_by, 
                             order=order.lower(), 
                             search_query=search_query,
                             is_search=bool(search_query))
    except Exception as e:
        print(f"List clients error: {str(e)}")
        traceback.print_exc()
        flash(f"Error: {str(e)}", "error")
        return render_template('clients.html', clients=[], is_search=False)


@app.route('/manual-sync')
@login_required
def manual_sync():
    """Manually trigger Google Drive sync (for admin only)"""
    try:
        print("Starting manual Google Drive sync...")
        synced = sync_drive_to_database()
        flash(f'✅ Synced {synced} documents from Google Drive', 'success')
        return redirect(url_for('list_clients'))
    except Exception as e:
        print(f"Sync error: {str(e)}")
        traceback.print_exc()
        flash(f'Error during sync: {str(e)}', 'error')
        return redirect(url_for('list_clients'))
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

# Replace the /forgot_password route with this corrected version

@app.route('/forgot_password', methods=['GET', 'POST'])
@limiter.limit("3 per hour")
def forgot_password():
    """Forgot password - Step 1: Username verification"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        
        if not username:
            flash('Please enter your username.', 'error')
            return render_template('forgot_password.html')
        
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            if USE_POSTGRESQL:
                cur.execute("SELECT id FROM users WHERE username = %s", (username,))
            else:
                cur.execute("SELECT id FROM users WHERE username = ?", (username,))
            
            user = cur.fetchone()
            cur.close()
            conn.close()
            
            if user:
                # Generate a simple alphanumeric reset code (uppercase + numbers only)
                # This makes it easier to type and matches the form styling
                reset_code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(6))
                
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
        except Exception as e:
            print(f"Forgot password error: {str(e)}")
            flash('An error occurred. Please try again.', 'error')
    
    return render_template('forgot_password.html')


@app.route('/reset_password_confirm', methods=['POST'])
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
    try:
        expiry_time = datetime.fromisoformat(session.get('reset_expiry'))
        if datetime.now() > expiry_time:
            session.pop('reset_username', None)
            session.pop('reset_code', None)
            session.pop('reset_expiry', None)
            flash('Reset code expired. Please request a new one.', 'error')
            return redirect(url_for('forgot_password'))
    except:
        flash('Session error. Please try again.', 'error')
        return redirect(url_for('forgot_password'))
    
    # Verify reset code
    import hmac
    if not hmac.compare_digest(reset_code, session.get('reset_code')):
        flash('Invalid reset code. Please check and try again.', 'error')
        log_activity("RESET_PASSWORD_FAILED", f"Invalid code for: {username}")
        return render_template('forgot_password.html', 
                             reset_code=session.get('reset_code'),
                             username=username)
    
    # Validate passwords
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
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        hashed_password = generate_password_hash(new_password)
        
        if USE_POSTGRESQL:
            cur.execute("UPDATE users SET password = ?, failed_login_attempts = 0, locked_until = NULL WHERE username = %s", 
                       (hashed_password, username))
        else:
            cur.execute("UPDATE users SET password = ?, failed_login_attempts = 0, locked_until = NULL WHERE username = ?", 
                       (hashed_password, username))
        
        conn.commit()
        cur.close()
        conn.close()
        
        # Clear session
        session.pop('reset_username', None)
        session.pop('reset_code', None)
        session.pop('reset_expiry', None)
        
        log_activity("RESET_PASSWORD_SUCCESS", f"Password reset for: {username}")
        flash('Password reset successful! Please login with your new password.', 'success')
        return redirect(url_for('login'))
    except Exception as e:
        print(f"Reset password error: {str(e)}")
        flash('An error occurred. Please try again.', 'error')
        return redirect(url_for('forgot_password'))
    
# Add these routes to your existing app.py file

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('register.html')
        
        if len(username) < 3:
            flash('Username must be at least 3 characters.', 'error')
            return render_template('register.html')
        
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            hashed_password = generate_password_hash(password)
            
            if USE_POSTGRESQL:
                cur.execute(
                    "INSERT INTO users (username, password, email, role, created_at) VALUES (%s, %s, %s, %s, %s)",
                    (username, hashed_password, email if email else None, 'user', datetime.now())
                )
            else:
                cur.execute(
                    "INSERT INTO users (username, password, email, role, created_at) VALUES (?, ?, ?, ?, ?)",
                    (username, hashed_password, email if email else None, 'user', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                )
            
            conn.commit()
            cur.close()
            conn.close()
            
            log_activity("USER_REGISTERED", f"New user registered: {username}")
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            print(f"Registration error: {str(e)}")
            flash('Username already exists. Choose a different one.', 'error')
            return render_template('register.html')
    
    return render_template('register.html')


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
        
        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return render_template('change_password.html')
        
        if len(new_password) < 6:
            flash('New password must be at least 6 characters.', 'error')
            return render_template('change_password.html')
        
        if new_password == current_password:
            flash('New password must be different from current password.', 'error')
            return render_template('change_password.html')
        
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
                cur.close()
                conn.close()
                return render_template('change_password.html')
            
            hashed_new_password = generate_password_hash(new_password)
            
            if USE_POSTGRESQL:
                cur.execute("UPDATE users SET password = %s WHERE id = %s", (hashed_new_password, user_id))
            else:
                cur.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_new_password, user_id))
            
            conn.commit()
            cur.close()
            conn.close()
            
            log_activity("PASSWORD_CHANGED", "User changed password")
            flash('Password changed successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            print(f"Change password error: {str(e)}")
            flash('An error occurred. Please try again.', 'error')
            return render_template('change_password.html')
    
    return render_template('change_password.html')


@app.route('/upload', methods=['POST'])
@login_required
@limiter.limit("10 per hour")
def upload():
    client_name = request.form.get('name', '').strip()
    
    if not client_name:
        flash('Client name is required.', 'error')
        return redirect(url_for('upload_page'))
    
    try:
        client_name = validate_client_name(client_name)
    except ValueError as e:
        flash(str(e), 'error')
        return redirect(url_for('upload_page'))
    
    upload_results = []
    
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
                cur.close()
                conn.close()
                return redirect(url_for('upload_page'))
            
            try:
                folder = drive.CreateFile({'title': client_name, 'parents': [{'id': ROOT_FOLDER_ID}], 'mimeType': 'application/vnd.google-apps.folder'})
                folder.Upload()
                folder_id = folder['id']
            except Exception as e:
                flash(f'Error creating folder: {str(e)}', 'error')
                cur.close()
                conn.close()
                return redirect(url_for('upload_page'))
            
            if USE_POSTGRESQL:
                cur.execute(
                    "INSERT INTO clients (name, folder_id, created_at, updated_at, created_by) VALUES (%s, %s, %s, %s, %s)",
                    (client_name, folder_id, datetime.now(), datetime.now(), session.get('user_id'))
                )
            else:
                cur.execute(
                    "INSERT INTO clients (name, folder_id, created_at, updated_at, created_by) VALUES (?, ?, ?, ?, ?)",
                    (client_name, folder_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), datetime.now().strftime("%Y-%m-%d %H:%M:%S"), session.get('user_id'))
                )
            
            conn.commit()
            client_id = cur.lastrowid if not USE_POSTGRESQL else cur.fetchone()[0]
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
                    
                    if USE_POSTGRESQL:
                        cur.execute("""
                            INSERT INTO documents (client_id, document_type, file_id, file_name, url, file_size, mime_type, upload_time, uploaded_by)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (client_id, document_type) 
                            DO UPDATE SET file_id = EXCLUDED.file_id, file_name = EXCLUDED.file_name, url = EXCLUDED.url, upload_time = EXCLUDED.upload_time
                        """, (client_id, doc_type, gfile['id'], gfile['title'], file_url, file.content_length, file.content_type, datetime.now(), session.get('user_id')))
                    else:
                        cur.execute("""
                            INSERT OR REPLACE INTO documents 
                            (client_id, document_type, file_id, file_name, url, file_size, mime_type, upload_time, uploaded_by)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (client_id, doc_type, gfile['id'], gfile['title'], file_url, file.content_length, file.content_type, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), session.get('user_id')))
                    
                    upload_results.append({
                        'type': doc_type,
                        'filename': gfile['title'],
                        'url': file_url
                    })
                except Exception as e:
                    flash(f'Error uploading {doc_type}: {str(e)}', 'error')
        
        if USE_POSTGRESQL:
            cur.execute("UPDATE clients SET updated_at = %s WHERE id = %s", (datetime.now(), client_id))
        else:
            cur.execute("UPDATE clients SET updated_at = ? WHERE id = ?", (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), client_id))
        
        conn.commit()
        cur.close()
        conn.close()
        
        log_activity("DOCUMENT_UPLOADED", f"Uploaded {len(upload_results)} documents for {client_name}")
        flash(f'Successfully uploaded {len(upload_results)} document(s)!', 'success')
        
        return render_template('upload.html', success=True, name=client_name, upload_results=upload_results)
    except Exception as e:
        print(f"Upload error: {str(e)}")
        traceback.print_exc()
        flash(f'Upload error: {str(e)}', 'error')
        return redirect(url_for('upload_page'))


@app.route('/fetch_data', methods=['POST'])
@login_required
def fetch_data():
    client_name = request.form.get('name', '').strip()
    
    if not client_name:
        flash('Client name is required.', 'error')
        return render_template('fetch.html')
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        if USE_POSTGRESQL:
            cur.execute("""
                SELECT c.id, c.name, c.created_at, c.updated_at, c.folder_id
                FROM clients c
                WHERE c.name ILIKE %s
            """, (f'%{client_name}%',))
        else:
            cur.execute("""
                SELECT c.id, c.name, c.created_at, c.updated_at, c.folder_id
                FROM clients c
                WHERE c.name LIKE ?
            """, (f'%{client_name}%',))
        
        client_row = cur.fetchone()
        
        if not client_row:
            cur.close()
            conn.close()
            return render_template('fetch.html', not_found=True, name=client_name)
        
        client_id = client_row[0]
        
        if USE_POSTGRESQL:
            cur.execute("""
                SELECT document_type, file_id, file_name, url, file_size, upload_time
                FROM documents WHERE client_id = %s
            """, (client_id,))
        else:
            cur.execute("""
                SELECT document_type, file_id, file_name, url, file_size, upload_time
                FROM documents WHERE client_id = ?
            """, (client_id,))
        
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
            'created_at': client_row[2],
            'updated_at': client_row[3],
            'folder_id': client_row[4],
            'documents': documents
        }
        
        cur.close()
        conn.close()
        
        log_activity("DOCUMENTS_VIEWED", f"Viewed documents for {client_row[1]}")
        return render_template('fetch.html', client=client)
    except Exception as e:
        print(f"Fetch data error: {str(e)}")
        traceback.print_exc()
        return render_template('fetch.html', error=str(e))


@app.route('/download_document', methods=['POST'])
@login_required
def download_document():
    file_id = request.form.get('file_id', '')
    
    if not file_id or not drive:
        return jsonify({'success': False, 'error': 'Invalid file or Google Drive not configured'})
    
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
        return jsonify({'success': False, 'error': str(e)})


@app.route('/delete_document', methods=['POST'])
@login_required
def delete_document():
    file_id = request.form.get('file_id', '')
    
    if not file_id or not drive:
        return jsonify({'success': False, 'error': 'Invalid file or Google Drive not configured'})
    
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
        cur.close()
        conn.close()
        
        log_activity("DOCUMENT_DELETED", f"Deleted file: {file_id}")
        return jsonify({'success': True, 'message': 'Document deleted successfully'})
    except Exception as e:
        print(f"Delete error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})


@app.route('/delete_client', methods=['POST'])
@login_required
def delete_client():
    client_name = request.form.get('name', '').strip()
    
    if not client_name:
        return jsonify({'success': False, 'error': 'Client name is required'})
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        if USE_POSTGRESQL:
            cur.execute("SELECT id, folder_id FROM clients WHERE name = %s", (client_name,))
        else:
            cur.execute("SELECT id, folder_id FROM clients WHERE name = ?", (client_name,))
        
        client = cur.fetchone()
        
        if not client:
            cur.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Client not found'})
        
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
        cur.close()
        conn.close()
        
        log_activity("CLIENT_DELETED", f"Deleted client: {client_name}")
        return jsonify({'success': True, 'message': 'Client and all documents deleted successfully'})
    except Exception as e:
        print(f"Delete client error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})


@app.route('/edit_client/<int:client_id>', methods=['POST'])
@login_required
def edit_client(client_id):
    new_name = request.form.get('new_name', '').strip()
    
    if not new_name:
        return jsonify({'success': False, 'error': 'New name is required'})
    
    try:
        new_name = validate_client_name(new_name)
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)})
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        if USE_POSTGRESQL:
            cur.execute("UPDATE clients SET name = %s WHERE id = %s", (new_name, client_id))
        else:
            cur.execute("UPDATE clients SET name = ? WHERE id = ?", (new_name, client_id))
        
        conn.commit()
        cur.close()
        conn.close()
        
        log_activity("CLIENT_RENAMED", f"Renamed client to: {new_name}")
        return jsonify({'success': True, 'message': 'Client name updated successfully'})
    except Exception as e:
        print(f"Edit client error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/quick_search', methods=['GET'])
@login_required
def api_quick_search():
    query = request.args.get('q', '').strip()
    
    if len(query) < 2:
        return jsonify({'results': []})
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        if USE_POSTGRESQL:
            cur.execute("""
                SELECT c.name, c.updated_at, COUNT(d.id) as doc_count
                FROM clients c
                LEFT JOIN documents d ON c.id = d.client_id
                WHERE c.name ILIKE %s
                GROUP BY c.id, c.name, c.updated_at
                LIMIT 10
            """, (f'%{query}%',))
        else:
            cur.execute("""
                SELECT c.name, c.updated_at, COUNT(d.id) as doc_count
                FROM clients c
                LEFT JOIN documents d ON c.id = d.client_id
                WHERE c.name LIKE ?
                GROUP BY c.id, c.name
                LIMIT 10
            """, (f'%{query}%',))
        
        results = []
        for row in cur.fetchall():
            results.append({
                'name': row[0],
                'updated_at': row[1][:10] if row[1] else '',
                'doc_count': row[2]
            })
        
        cur.close()
        conn.close()
        
        return jsonify({'results': results})
    except Exception as e:
        print(f"Quick search error: {str(e)}")
        return jsonify({'results': [], 'error': str(e)})

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