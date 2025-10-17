from flask import Flask, render_template, request, Response, send_file, jsonify, redirect, url_for, session, flash
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
import random
import string

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-change-this-in-production')

# Configuration
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'pdf'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
UPLOAD_FOLDER = 'uploads'
DOCUMENT_TYPES = ['datasheet', 'aadhaar', 'pan', 'bank_account']

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_file_size(file):
    """Check if file size is within limits"""
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    return size <= MAX_FILE_SIZE


def login_required(f):
    """Login required decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# Google Drive Setup
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
        
        # Create client config
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
        
        # Save client config to persistent file
        client_secrets_file = 'client_secrets.json'
        with open(client_secrets_file, 'w') as f:
            json.dump(client_config, f)
        
        # Setup GoogleAuth
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
            print("✓ Using existing refresh token")
        else:
            print("⚠ First time setup - please authenticate with Google Drive")
            print("⚠ After authentication, save the refresh token to GOOGLE_REFRESH_TOKEN in .env")
            gauth.GetFlow()
            gauth.flow.params.clear()
            gauth.flow.params.update({
                'access_type': 'offline',
                'prompt': 'consent',
                'response_type': 'code'
            })
            gauth.LocalWebserverAuth()
            print(f"✓ Authentication complete. Save this refresh token: {gauth.credentials.refresh_token}")
        
        return gauth
    
    except Exception as e:
        print(f"✗ Error setting up Google Drive authentication: {str(e)}")
        traceback.print_exc()
        raise


try:
    gauth = setup_google_auth()
    drive = GoogleDrive(gauth)
    print("✓ Google Drive initialized successfully")
except Exception as e:
    print(f"✗ Failed to initialize Google Drive: {str(e)}")
    drive = None

# Google Drive Root Folder ID
ROOT_FOLDER_ID = os.getenv('GOOGLE_DRIVE_FOLDER_ID', "1ADorPsFHr7HYRMPR7zQdtbSAazWIk7o9")


# Database setup
def init_db():
    """Initialize database with proper error handling"""
    try:
        with sqlite3.connect("database.db") as conn:
            # Users table
            conn.execute('''CREATE TABLE IF NOT EXISTS users (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                username TEXT NOT NULL UNIQUE,
                                password TEXT NOT NULL,
                                email TEXT,
                                role TEXT DEFAULT 'user',
                                created_at TEXT NOT NULL
                            )''')
            
            # Clients table
            conn.execute('''CREATE TABLE IF NOT EXISTS clients (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                name TEXT NOT NULL UNIQUE,
                                folder_id TEXT NOT NULL UNIQUE,
                                created_at TEXT NOT NULL,
                                updated_at TEXT NOT NULL,
                                created_by INTEGER,
                                FOREIGN KEY (created_by) REFERENCES users (id)
                            )''')
            
            # Documents table
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
            
            # Activity logs table
            conn.execute('''CREATE TABLE IF NOT EXISTS activity_logs (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                user_id INTEGER,
                                action TEXT NOT NULL,
                                details TEXT,
                                timestamp TEXT NOT NULL,
                                FOREIGN KEY (user_id) REFERENCES users (id)
                            )''')
            
            # Create indexes
            conn.execute('CREATE INDEX IF NOT EXISTS idx_client_name ON clients(name)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_client_id ON documents(client_id)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_doc_type ON documents(document_type)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_username ON users(username)')
            
            # Create default admin user if not exists
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users")
            if cursor.fetchone()[0] == 0:
                admin_password = generate_password_hash('admin123')
                cursor.execute(
                    "INSERT INTO users (username, password, email, role, created_at) VALUES (?, ?, ?, ?, ?)",
                    ('admin', admin_password, 'admin@example.com', 'admin', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                )
                print("✓ Default admin user created (username: admin, password: admin123)")
                print("⚠ IMPORTANT: Change the default password after first login!")
            
        print("✓ Database initialized successfully")
    except Exception as e:
        print(f"✗ Error initializing database: {str(e)}")
        raise


init_db()


def log_activity(action, details=""):
    """Log user activity"""
    try:
        user_id = session.get('user_id')
        with sqlite3.connect("database.db") as conn:
            conn.execute(
                "INSERT INTO activity_logs (user_id, action, details, timestamp) VALUES (?, ?, ?, ?)",
                (user_id, action, details, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            )
    except Exception as e:
        print(f"Error logging activity: {str(e)}")


def get_or_create_client_folder(client_name):
    """Get existing or create new folder for client in Google Drive"""
    try:
        # Check if client exists in database
        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()
            cur.execute("SELECT folder_id FROM clients WHERE name = ?", (client_name,))
            result = cur.fetchone()
            
            if result:
                return result[0]
        
        # Create new folder in Google Drive
        folder_metadata = {
            'title': client_name,
            'mimeType': 'application/vnd.google-apps.folder',
            'parents': [{'id': ROOT_FOLDER_ID}]
        }
        folder = drive.CreateFile(folder_metadata)
        folder.Upload()
        
        # Make folder accessible
        folder.InsertPermission({'type': 'anyone', 'value': 'anyone', 'role': 'reader'})
        
        # Save to database
        with sqlite3.connect("database.db") as conn:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            user_id = session.get('user_id')
            conn.execute(
                "INSERT INTO clients (name, folder_id, created_at, updated_at, created_by) VALUES (?, ?, ?, ?, ?)",
                (client_name, folder['id'], now, now, user_id)
            )
        
        log_activity("CREATE_CLIENT", f"Created client: {client_name}")
        print(f"✓ Created folder for client: {client_name}")
        return folder['id']
    
    except Exception as e:
        print(f"✗ Error creating client folder: {str(e)}")
        raise


def get_client_id(client_name):
    """Get client ID from database"""
    with sqlite3.connect("database.db") as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM clients WHERE name = ?", (client_name,))
        result = cur.fetchone()
        return result[0] if result else None


def cleanup_temp_file(filepath):
    """Safely remove temporary file"""
    try:
        if os.path.exists(filepath):
            os.remove(filepath)
    except Exception as e:
        print(f"Warning: Could not remove temp file {filepath}: {str(e)}")


# Authentication Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return render_template('login.html')
        
        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, username, password, role FROM users WHERE username = ?", (username,))
            user = cur.fetchone()
        
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[3]
            log_activity("LOGIN", f"User logged in: {username}")
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'error')
            log_activity("LOGIN_FAILED", f"Failed login attempt: {username}")
    
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Register new user"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        email = request.form.get('email', '').strip()
        
        # Validation
        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('register.html')
        
        if len(username) < 3:
            flash('Username must be at least 3 characters long.', 'error')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        
        # Check if username exists
        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
            if cur.fetchone()[0] > 0:
                flash('Username already exists.', 'error')
                return render_template('register.html')
            
            # Create user
            hashed_password = generate_password_hash(password)
            cur.execute(
                "INSERT INTO users (username, password, email, role, created_at) VALUES (?, ?, ?, ?, ?)",
                (username, hashed_password, email, 'user', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            )
            conn.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change user password"""
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        if not current_password or not new_password or not confirm_password:
            flash('All fields are required.', 'error')
            return render_template('change_password.html')
        
        if len(new_password) < 6:
            flash('New password must be at least 6 characters long.', 'error')
            return render_template('change_password.html')
        
        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return render_template('change_password.html')
        
        if new_password == current_password:
            flash('New password must be different from current password.', 'error')
            return render_template('change_password.html')
        
        # Verify current password
        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()
            cur.execute("SELECT password FROM users WHERE id = ?", (session['user_id'],))
            user = cur.fetchone()
            
            if not user or not check_password_hash(user[0], current_password):
                flash('Current password is incorrect.', 'error')
                log_activity("PASSWORD_CHANGE_FAILED", "Incorrect current password")
                return render_template('change_password.html')
            
            # Update password
            hashed_password = generate_password_hash(new_password)
            cur.execute("UPDATE users SET password = ? WHERE id = ?", 
                       (hashed_password, session['user_id']))
            conn.commit()
        
        log_activity("PASSWORD_CHANGED", "Password updated successfully")
        flash('Password changed successfully! Please login again.', 'success')
        
        # Logout user after password change
        session.clear()
        return redirect(url_for('login'))
    
    return render_template('change_password.html')


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """Forgot password - Step 1: Verify username"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        
        if not username:
            flash('Please enter your username.', 'error')
            return render_template('forgot_password.html')
        
        # Check if user exists
        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()
            cur.execute("SELECT id FROM users WHERE username = ?", (username,))
            user = cur.fetchone()
            
            if not user:
                flash('Username not found.', 'error')
                log_activity("FORGOT_PASSWORD_FAILED", f"Username not found: {username}")
                return render_template('forgot_password.html')
        
        # Generate 6-digit reset code
        reset_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        
        # Store reset code in session (expires with session)
        session['reset_code'] = reset_code
        session['reset_username'] = username
        session['reset_code_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        log_activity("FORGOT_PASSWORD_INITIATED", f"Reset code generated for: {username}")
        
        return render_template('forgot_password.html', reset_code=reset_code, username=username)
    
    return render_template('forgot_password.html')


@app.route('/reset_password_confirm', methods=['POST'])
def reset_password_confirm():
    """Forgot password - Step 2: Reset with code"""
    username = request.form.get('username', '').strip()
    reset_code = request.form.get('reset_code', '').strip().upper()
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    # Validation
    if not all([username, reset_code, new_password, confirm_password]):
        flash('All fields are required.', 'error')
        return redirect(url_for('forgot_password'))
    
    if len(new_password) < 6:
        flash('Password must be at least 6 characters long.', 'error')
        return redirect(url_for('forgot_password'))
    
    if new_password != confirm_password:
        flash('Passwords do not match.', 'error')
        return redirect(url_for('forgot_password'))
    
    # Verify reset code
    if 'reset_code' not in session or 'reset_username' not in session:
        flash('Reset session expired. Please try again.', 'error')
        return redirect(url_for('forgot_password'))
    
    if session['reset_username'] != username:
        flash('Invalid username.', 'error')
        return redirect(url_for('forgot_password'))
    
    if session['reset_code'] != reset_code:
        flash('Invalid reset code. Please try again.', 'error')
        log_activity("RESET_PASSWORD_FAILED", f"Invalid code for: {username}")
        return redirect(url_for('forgot_password'))
    
    # Check if code expired (15 minutes)
    code_time = datetime.strptime(session['reset_code_time'], "%Y-%m-%d %H:%M:%S")
    if datetime.now() - code_time > timedelta(minutes=15):
        flash('Reset code expired. Please request a new one.', 'error')
        session.pop('reset_code', None)
        session.pop('reset_username', None)
        session.pop('reset_code_time', None)
        return redirect(url_for('forgot_password'))
    
    # Update password
    try:
        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()
            hashed_password = generate_password_hash(new_password)
            cur.execute("UPDATE users SET password = ? WHERE username = ?", 
                       (hashed_password, username))
            conn.commit()
        
        # Clear reset session
        session.pop('reset_code', None)
        session.pop('reset_username', None)
        session.pop('reset_code_time', None)
        
        log_activity("PASSWORD_RESET_SUCCESS", f"Password reset for: {username}")
        flash('Password reset successful! Please login with your new password.', 'success')
        return redirect(url_for('login'))
    
    except Exception as e:
        print(f"Password reset error: {str(e)}")
        flash('An error occurred. Please try again.', 'error')
        return redirect(url_for('forgot_password'))


@app.route('/logout')
@login_required
def logout():
    """Logout user"""
    username = session.get('username')
    log_activity("LOGOUT", f"User logged out: {username}")
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))


# Main Routes
@app.route('/')
@login_required
def home():
    """Home page with upload form"""
    return render_template('upload.html')


@app.route('/upload', methods=['POST'])
@login_required
def upload():
    """Upload or update documents for a client"""
    if not drive:
        flash("Google Drive not initialized. Check server logs.", "error")
        return render_template('upload.html')
    
    try:
        name = request.form.get('name', '').strip()
        
        # Validation
        if not name:
            flash("Please enter a client name", "error")
            return render_template('upload.html')
        
        # Get uploaded files
        files = {
            'datasheet': request.files.get('datasheet'),
            'aadhaar': request.files.get('aadhaar'),
            'pan': request.files.get('pan'),
            'bank_account': request.files.get('bank_account')
        }
        
        # Check if at least ONE file is uploaded
        has_files = any(file and file.filename != '' for file in files.values())
        if not has_files:
            flash("Please upload at least one document!", "error")
            return render_template('upload.html')
        
        # Validate all uploaded files
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
        
        # Get or create client folder
        folder_id = get_or_create_client_folder(name)
        client_id = get_client_id(name)
        user_id = session.get('user_id')
        
        # Check for existing documents to delete old versions
        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()
            for doc_type in uploaded_files.keys():
                cur.execute(
                    "SELECT file_id FROM documents WHERE client_id = ? AND document_type = ?",
                    (client_id, doc_type)
                )
                old_file = cur.fetchone()
                
                if old_file:
                    # Delete old file from Google Drive
                    try:
                        old_gfile = drive.CreateFile({'id': old_file[0]})
                        old_gfile.Delete()
                        log_activity("REPLACE_DOCUMENT", f"Replaced {doc_type} for {name}")
                    except Exception as e:
                        print(f"Warning: Could not delete old file: {str(e)}")
                    
                    # Delete old record from database
                    conn.execute(
                        "DELETE FROM documents WHERE client_id = ? AND document_type = ?",
                        (client_id, doc_type)
                    )
        
        # Upload each file
        upload_results = []
        for doc_type, file in uploaded_files.items():
            filename = secure_filename(file.filename)
            temp_path = os.path.join(UPLOAD_FOLDER, filename)
            
            try:
                # Save temporarily
                file.save(temp_path)
                file_size = os.path.getsize(temp_path)
                
                # Upload to Google Drive
                gfile = drive.CreateFile({
                    'title': f"{name}_{doc_type}_{filename}",
                    'parents': [{'id': folder_id}]
                })
                gfile.SetContentFile(temp_path)
                gfile.Upload()
                gfile.content.close()
                
                # Make file public
                gfile.InsertPermission({'type': 'anyone', 'value': 'anyone', 'role': 'reader'})
                
                # Get file info
                gfile.FetchMetadata()
                file_url = f"https://drive.google.com/uc?export=download&id={gfile['id']}"
                mime_type = gfile.get('mimeType', 'image/jpeg')
                
                # Save to database
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
                    'url': file_url,
                    'action': 'updated' if old_file else 'uploaded'
                })
                
                cleanup_temp_file(temp_path)
                log_activity("UPLOAD_DOCUMENT", f"Uploaded {doc_type} for {name}")
                
            except Exception as upload_error:
                cleanup_temp_file(temp_path)
                raise upload_error
        
        # Update client updated_at
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


@app.route('/update_documents/<client_name>')
@login_required
def update_documents_page(client_name):
    """Page to update/add documents for existing client"""
    try:
        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT c.id, c.name, c.folder_id
                FROM clients c
                WHERE c.name = ?
            """, (client_name,))
            client = cur.fetchone()
            
            if not client:
                flash(f"Client '{client_name}' not found!", "error")
                return redirect(url_for('list_clients'))
            
            client_id = client[0]
            
            # Get existing documents
            cur.execute("""
                SELECT document_type, file_name, upload_time
                FROM documents
                WHERE client_id = ?
            """, (client_id,))
            
            existing_docs = {row[0]: {'filename': row[1], 'upload_time': row[2]} 
                           for row in cur.fetchall()}
        
        return render_template('update_documents.html', 
                             client_name=client_name, 
                             existing_docs=existing_docs)
    
    except Exception as e:
        print(f"Error loading update page: {str(e)}")
        flash(f"Error: {str(e)}", "error")
        return redirect(url_for('list_clients'))


@app.route('/fetch')
@login_required
def fetch_page():
    """Fetch page"""
    return render_template('fetch.html')


@app.route('/fetch_data', methods=['POST'])
@login_required
def fetch_data():
    """Fetch all documents for a client - IMPROVED VERSION"""
    try:
        name = request.form.get('name', '').strip()
        
        if not name:
            flash("Please enter a name", "error")
            return render_template('fetch.html')
        
        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()
            
            # Try exact match first
            cur.execute("""
                SELECT c.id, c.name, c.folder_id, c.created_at, c.updated_at
                FROM clients c
                WHERE c.name = ?
            """, (name,))
            client = cur.fetchone()
            
            # If no exact match, try case-insensitive
            if not client:
                cur.execute("""
                    SELECT c.id, c.name, c.folder_id, c.created_at, c.updated_at
                    FROM clients c
                    WHERE LOWER(c.name) = LOWER(?)
                """, (name,))
                client = cur.fetchone()
            
            # If still not found, try partial match
            if not client:
                cur.execute("""
                    SELECT c.id, c.name, c.folder_id, c.created_at, c.updated_at
                    FROM clients c
                    WHERE c.name LIKE ?
                """, (f'%{name}%',))
                matches = cur.fetchall()
                
                if matches:
                    # Show suggestions
                    suggestions = [m[1] for m in matches]
                    flash(f"Client '{name}' not found. Did you mean: {', '.join(suggestions)}?", "error")
                    return render_template('fetch.html', suggestions=suggestions)
                else:
                    # Definitely not found
                    return render_template('fetch.html', not_found=True, name=name)
            
            client_id, client_name, folder_id, created_at, updated_at = client
            
            # Get all documents for this client
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
                    'file_size': file_size if file_size else 0,  # Handle NULL
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


@app.route('/clients')
@login_required
def list_clients():
    """List all clients with sorting and filtering"""
    try:
        # Get query parameters
        sort_by = request.args.get('sort', 'updated_at')
        order = request.args.get('order', 'desc')
        filter_docs = request.args.get('filter_docs', '')
        search_query = request.args.get('search', '')
        
        # Validate sort column
        valid_sorts = ['name', 'created_at', 'updated_at', 'doc_count']
        if sort_by not in valid_sorts:
            sort_by = 'updated_at'
        
        # Validate order
        order = 'ASC' if order == 'asc' else 'DESC'
        
        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()
            
            # Build query
            query = """
                SELECT c.id, c.name, c.created_at, c.updated_at, COUNT(d.id) as doc_count
                FROM clients c
                LEFT JOIN documents d ON c.id = d.client_id
            """
            
            conditions = []
            params = []
            
            # Apply search filter
            if search_query:
                conditions.append("c.name LIKE ?")
                params.append(f'%{search_query}%')
            
            # Apply document count filter
            if filter_docs:
                if filter_docs == '0':
                    conditions.append("(SELECT COUNT(*) FROM documents WHERE client_id = c.id) = 0")
                elif filter_docs == '1-3':
                    conditions.append("(SELECT COUNT(*) FROM documents WHERE client_id = c.id) BETWEEN 1 AND 3")
                elif filter_docs == '4':
                    conditions.append("(SELECT COUNT(*) FROM documents WHERE client_id = c.id) = 4")
            
            # Add conditions
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            
            query += " GROUP BY c.id"
            
            # Add sorting
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
        flash(f"Error: {str(e)}", "error")
        return render_template('clients.html', clients=[])


@app.route('/edit_client/<int:client_id>', methods=['POST'])
@login_required
def edit_client(client_id):
    """Edit client name"""
    try:
        new_name = request.form.get('new_name', '').strip()
        
        if not new_name:
            return jsonify({'success': False, 'error': 'Client name cannot be empty'})
        
        # Get old name for logging
        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()
            cur.execute("SELECT name FROM clients WHERE id = ?", (client_id,))
            result = cur.fetchone()
            
            if not result:
                return jsonify({'success': False, 'error': 'Client not found'})
            
            old_name = result[0]
            
            # Check if new name already exists
            cur.execute("SELECT COUNT(*) FROM clients WHERE name = ? AND id != ?", (new_name, client_id))
            if cur.fetchone()[0] > 0:
                return jsonify({'success': False, 'error': 'Client name already exists'})
            
            # Update client name
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


@app.route('/image/<file_id>')
@login_required
def serve_image(file_id):
    """Serve image from Google Drive through local proxy"""
    if not drive:
        return "Google Drive not initialized", 503
    
    try:
        gfile = drive.CreateFile({'id': file_id})
        gfile.FetchMetadata()
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.jpg') as temp_file:
            temp_path = temp_file.name
        
        try:
            # Download content to temp file
            gfile.GetContentFile(temp_path)
            
            # Read file content
            with open(temp_path, 'rb') as f:
                content_bytes = f.read()
            
            # Clean up
            cleanup_temp_file(temp_path)
            
            # Return response
            response = Response(content_bytes, mimetype=gfile.get('mimeType', 'image/jpeg'))
            response.headers['Content-Type'] = gfile.get('mimeType', 'image/jpeg')
            response.headers['Content-Length'] = str(len(content_bytes))
            response.headers['Cache-Control'] = 'public, max-age=3600'
            
            return response
        
        except Exception as e:
            cleanup_temp_file(temp_path)
            raise e
    
    except Exception as e:
        print(f"Error serving image: {str(e)}")
        traceback.print_exc()
        return f"Error loading image: {str(e)}", 404


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
        
        # Determine file extension
        mime_type = gfile.get('mimeType', 'image/jpeg')
        if 'png' in mime_type:
            suffix = '.png'
        elif 'jpeg' in mime_type or 'jpg' in mime_type:
            suffix = '.jpg'
        elif 'pdf' in mime_type:
            suffix = '.pdf'
        else:
            suffix = '.jpg'
        
        # Create temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
            temp_path = temp_file.name
        
        # Download content
        gfile.GetContentFile(temp_path)
        
        # Send file
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


@app.route('/delete_client', methods=['POST'])
@login_required
def delete_client():
    """Delete entire client folder and all documents"""
    if not drive:
        return jsonify({'success': False, 'error': 'Google Drive not initialized'}), 503
    
    try:
        name = request.form.get('name', '').strip()
        
        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, folder_id FROM clients WHERE name = ?", (name,))
            result = cur.fetchone()
        
        if result:
            client_id, folder_id = result
            
            try:
                # Delete folder from Google Drive (this deletes all files inside)
                folder = drive.CreateFile({'id': folder_id})
                folder.Delete()
                
                # Delete from database
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
        
        # Get document info
        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()
            cur.execute("SELECT document_type, client_id FROM documents WHERE file_id = ?", (file_id,))
            result = cur.fetchone()
            
            if not result:
                return jsonify({'success': False, 'error': 'Document not found'}), 404
            
            doc_type, client_id = result
        
        # Delete from Google Drive
        try:
            gfile = drive.CreateFile({'id': file_id})
            gfile.Delete()
        except Exception as e:
            print(f"Warning: Could not delete from Drive: {str(e)}")
        
        # Delete from database
        with sqlite3.connect("database.db") as conn:
            conn.execute("DELETE FROM documents WHERE file_id = ?", (file_id,))
        
        log_activity("DELETE_DOCUMENT", f"Deleted {doc_type} document")
        return jsonify({'success': True, 'message': f'Successfully deleted {doc_type}'})
    
    except Exception as e:
        print(f"Delete document error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard with statistics"""
    try:
        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()
            
            # Get statistics
            cur.execute("SELECT COUNT(*) FROM clients")
            total_clients = cur.fetchone()[0]
            
            cur.execute("SELECT COUNT(*) FROM documents")
            total_docs = cur.fetchone()[0]
            
            cur.execute("SELECT COUNT(*) FROM users")
            total_users = cur.fetchone()[0]
            
            # Recent activity
            cur.execute("""
                SELECT u.username, a.action, a.details, a.timestamp
                FROM activity_logs a
                LEFT JOIN users u ON a.user_id = u.id
                ORDER BY a.timestamp DESC
                LIMIT 10
            """)
            recent_activity = cur.fetchall()
            
            # Document type distribution
            cur.execute("""
                SELECT document_type, COUNT(*) as count
                FROM documents
                GROUP BY document_type
                ORDER BY count DESC
            """)
            doc_distribution = cur.fetchall()
            
            # Recent clients
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
        
        print(f"DEBUG: Dashboard stats - Clients: {total_clients}, Docs: {total_docs}, Users: {total_users}")
        
        return render_template('dashboard.html', stats=stats)
    
    except Exception as e:
        print(f"Dashboard error: {str(e)}")
        import traceback
        traceback.print_exc()
        flash(f"Error loading dashboard: {str(e)}", "error")
        
        # Return empty stats on error
        stats = {
            'total_clients': 0,
            'total_docs': 0,
            'total_users': 0,
            'recent_activity': [],
            'doc_distribution': [],
            'recent_clients': []
        }
        return render_template('dashboard.html', stats=stats)


@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    return render_template('404.html'), 404


@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors"""
    flash("Internal server error. Please try again.", "error")
    return redirect(url_for('home')), 500

def auto_sync_on_startup():
    # ... copy the function from artifact ...
    pass

if __name__ == '__main__':
    # Run sync before starting app
    try:
        print("🔄 Running auto-sync...")
        auto_sync_on_startup()
    except Exception as e:
        print(f"⚠️ Sync error: {e}")
    
    # Start app
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0', port=int(os.getenv('PORT', 5000)))