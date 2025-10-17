#!/usr/bin/env python3
"""
Auto-sync script for Render deployment
Add this to your app.py or run as startup command
"""

from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive
import sqlite3
from datetime import datetime
import os
import json

def auto_sync_on_startup():
    """Run sync automatically when app starts"""
    print("🔄 Starting auto-sync from Google Drive...")
    
    # Check if sync was already done recently
    sync_marker = "last_sync.txt"
    if os.path.exists(sync_marker):
        with open(sync_marker, 'r') as f:
            last_sync = f.read().strip()
            # Skip if synced in last 24 hours
            try:
                last_time = datetime.fromisoformat(last_sync)
                time_diff = datetime.now() - last_time
                if time_diff.total_seconds() < 86400:  # 24 hours
                    print(f"⏭️  Skipping sync (last synced {time_diff.seconds // 3600}h ago)")
                    return
            except:
                pass
    
    try:
        # Setup Drive
        drive = setup_google_drive()
        if not drive:
            print("⚠️  Could not connect to Drive, skipping sync")
            return
        
        # Get root folder
        root_folder_id = os.getenv('GOOGLE_DRIVE_FOLDER_ID')
        if not root_folder_id:
            print("⚠️  No root folder ID, skipping sync")
            return
        
        # Scan and sync
        clients = scan_drive_folders(drive, root_folder_id)
        if clients:
            synced = sync_to_database_silent(clients)
            print(f"✅ Auto-sync complete: {synced} items synced")
            
            # Mark sync time
            with open(sync_marker, 'w') as f:
                f.write(datetime.now().isoformat())
        else:
            print("⚠️  No folders found in Drive")
            
    except Exception as e:
        print(f"⚠️  Auto-sync error: {str(e)}")
        # Don't crash the app if sync fails


def setup_google_drive():
    """Setup Drive connection"""
    try:
        client_id = os.getenv('GOOGLE_CLIENT_ID')
        client_secret = os.getenv('GOOGLE_CLIENT_SECRET')
        refresh_token = os.getenv('GOOGLE_REFRESH_TOKEN')
        
        if not all([client_id, client_secret, refresh_token]):
            return None
        
        client_config = {
            "installed": {
                "client_id": client_id,
                "client_secret": client_secret,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": ["http://localhost"]
            }
        }
        
        with open('temp_client_secrets.json', 'w') as f:
            json.dump(client_config, f)
        
        gauth = GoogleAuth(settings={
            'client_config_backend': 'file',
            'client_config_file': 'temp_client_secrets.json',
            'save_credentials': False,
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
        
        return GoogleDrive(gauth)
        
    except Exception as e:
        print(f"Drive setup error: {str(e)}")
        return None


def scan_drive_folders(drive, root_folder_id):
    """Scan Drive folders"""
    try:
        query = f"'{root_folder_id}' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false"
        folder_list = drive.ListFile({'q': query}).GetList()
        
        clients = []
        for folder in folder_list:
            files_query = f"'{folder['id']}' in parents and trashed=false"
            files_list = drive.ListFile({'q': files_query}).GetList()
            
            clients.append({
                'name': folder['title'],
                'folder_id': folder['id'],
                'created_date': folder.get('createdDate', datetime.now().isoformat()),
                'modified_date': folder.get('modifiedDate', datetime.now().isoformat()),
                'files': files_list
            })
        
        return clients
    except:
        return []


def sync_to_database_silent(clients):
    """Sync to database without verbose output"""
    synced_count = 0
    
    try:
        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()
            
            # Get existing clients
            cur.execute("SELECT name, folder_id FROM clients")
            existing = {name: folder_id for name, folder_id in cur.fetchall()}
            
            for client in clients:
                name = client['name']
                folder_id = client['folder_id']
                created_date = client['created_date'][:19].replace('T', ' ')
                modified_date = client['modified_date'][:19].replace('T', ' ')
                
                # Add or update client
                if name not in existing:
                    cur.execute(
                        "INSERT INTO clients (name, folder_id, created_at, updated_at) VALUES (?, ?, ?, ?)",
                        (name, folder_id, created_date, modified_date)
                    )
                    client_id = cur.lastrowid
                    synced_count += 1
                else:
                    cur.execute("SELECT id FROM clients WHERE name = ?", (name,))
                    client_id = cur.fetchone()[0]
                
                # Add documents
                for file in client['files']:
                    file_id = file['id']
                    file_name = file['title']
                    
                    # Determine doc type
                    file_lower = file_name.lower()
                    if 'datasheet' in file_lower:
                        doc_type = 'datasheet'
                    elif 'aadhaar' in file_lower or 'aadhar' in file_lower:
                        doc_type = 'aadhaar'
                    elif 'pan' in file_lower:
                        doc_type = 'pan'
                    elif 'bank' in file_lower:
                        doc_type = 'bank_account'
                    else:
                        doc_type = 'datasheet'
                    
                    # Check if exists
                    cur.execute("SELECT COUNT(*) FROM documents WHERE file_id = ?", (file_id,))
                    if cur.fetchone()[0] == 0:
                        try:
                            cur.execute(
                                """INSERT INTO documents 
                                   (client_id, document_type, file_id, file_name, url, file_size, mime_type, upload_time)
                                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                                (client_id, doc_type, file_id, file_name,
                                 f"https://drive.google.com/uc?export=download&id={file_id}",
                                 int(file.get('fileSize', 0)),
                                 file.get('mimeType', 'application/octet-stream'),
                                 file.get('createdDate', datetime.now().isoformat())[:19].replace('T', ' '))
                            )
                            synced_count += 1
                        except:
                            pass
            
            conn.commit()
        
        return synced_count
    except:
        return 0


# Add this to your app.py __main__ section:
if __name__ == '__main__':
    # Run auto-sync on startup
    try:
        auto_sync_on_startup()
    except Exception as e:
        print(f"Sync error on startup: {str(e)}")
    
    # Start Flask app
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'

    # Ensure a Flask app exists: try to import app from app.py, otherwise create one.
    try:
        from app import app  # reuse an existing Flask app if present
    except Exception:
        from flask import Flask
        app = Flask(__name__)

    app.run(debug=debug_mode, host='0.0.0.0', port=5000)