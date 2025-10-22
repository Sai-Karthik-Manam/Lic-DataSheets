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
    """Sync all clients and documents from Google Drive to database"""
    if not drive:
        print("Google Drive not initialized")
        return 0

    try:
        print("Starting Google Drive sync...")
        synced_count = 0
        
        query = f"'{ROOT_FOLDER_ID}' in parents and trashed=false"
        folder_list = drive.ListFile({'q': query, 'maxResults': 50}).GetList()
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
                    
                    print(f"Added client: {folder_name}")
                
                # Sync files in folder
                files_query = f"'{folder_id}' in parents and trashed=false"
                try:
                    files_list = drive.ListFile({'q': files_query, 'maxResults': 50}).GetList()
                except Exception as e:
                    print(f"⚠️ Could not fetch files for {folder_name}: {e}")
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
                            # Skip files we can't categorize
                            print(f"  Skipping uncategorized file: {file['title']}")
                            continue
                        
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
                        print(f"  Skipping file {file.get('title', '?')}: {e}")
                        continue
                
                conn.commit()
                time.sleep(0.5)  # Rate limiting
                
            except Exception as e:
                print(f"Error syncing folder {folder.get('title', '?')}: {str(e)}")
                conn.rollback()
                continue
        
        cur.close()
        conn.close()
        print(f"✅ Sync complete! {synced_count} documents processed")
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
    """List all clients - NO sync during page load (prevents timeout)"""
    try:
        sort_by = request.args.get('sort', 'updated_at')
        order = request.args.get('order', 'desc')
        search_query = request.args.get('search', '')
        
        order = 'ASC' if order == 'asc' else 'DESC'
        valid_sorts = ['name', 'created_at', 'updated_at']
        
        if sort_by not in valid_sorts:
            sort_by = 'updated_at'
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        if USE_POSTGRESQL:
            cur.execute("""
                SELECT c.id, c.name, c.created_at, c.updated_at, COUNT(d.id) as doc_count
                FROM clients c
                LEFT JOIN documents d ON c.id = d.client_id
                GROUP BY c.id
                ORDER BY c.updated_at DESC
            """)
        else:
            cur.execute("""
                SELECT c.id, c.name, c.created_at, c.updated_at, COUNT(d.id) as doc_count
                FROM clients c
                LEFT JOIN documents d ON c.id = d.client_id
                GROUP BY c.id
                ORDER BY c.updated_at DESC
            """)
        
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
                             search_query=search_query)
    except Exception as e:
        print(f"List clients error: {str(e)}")
        traceback.print_exc()
        flash(f"Error: {str(e)}", "error")
        return render_template('clients.html', clients=[])


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

if __name__ == '__main__':
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    port = int(os.getenv('PORT', 5000))
    app.run(debug=debug_mode, host='0.0.0.0', port=port)