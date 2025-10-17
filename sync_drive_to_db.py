#!/usr/bin/env python3
"""
Sync Google Drive folders to database
This will scan your Drive and add missing clients/documents to database
"""

from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive
import sqlite3
from datetime import datetime
import os
import json
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def setup_google_drive():
    """Setup Google Drive connection"""
    try:
        client_id = os.getenv('GOOGLE_CLIENT_ID')
        client_secret = os.getenv('GOOGLE_CLIENT_SECRET')
        refresh_token = os.getenv('GOOGLE_REFRESH_TOKEN')
        
        # Create client config
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
        
        drive = GoogleDrive(gauth)
        print("✅ Connected to Google Drive")
        return drive
        
    except Exception as e:
        print(f"❌ Error connecting to Drive: {str(e)}")
        return None


def scan_drive_folders(drive, root_folder_id):
    """Scan all folders in the root folder"""
    print("\n🔍 Scanning Google Drive folders...")
    print("-" * 60)
    
    try:
        # Get all folders in root folder
        query = f"'{root_folder_id}' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false"
        folder_list = drive.ListFile({'q': query}).GetList()
        
        print(f"Found {len(folder_list)} folder(s) in Google Drive:\n")
        
        clients = []
        for folder in folder_list:
            folder_name = folder['title']
            folder_id = folder['id']
            created_date = folder.get('createdDate', datetime.now().isoformat())
            modified_date = folder.get('modifiedDate', datetime.now().isoformat())
            
            # Get files in this folder
            files_query = f"'{folder_id}' in parents and trashed=false"
            files_list = drive.ListFile({'q': files_query}).GetList()
            
            print(f"📁 {folder_name}")
            print(f"   • Folder ID: {folder_id}")
            print(f"   • Files: {len(files_list)}")
            print(f"   • Created: {created_date[:10]}")
            print()
            
            clients.append({
                'name': folder_name,
                'folder_id': folder_id,
                'created_date': created_date,
                'modified_date': modified_date,
                'files': files_list
            })
        
        return clients
        
    except Exception as e:
        print(f"❌ Error scanning Drive: {str(e)}")
        import traceback
        traceback.print_exc()
        return []


def sync_to_database(clients):
    """Sync Drive folders to database"""
    print("\n" + "=" * 60)
    print("💾 Syncing to Database")
    print("=" * 60)
    
    try:
        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()
            
            # Check existing clients
            cur.execute("SELECT name, folder_id FROM clients")
            existing = {name: folder_id for name, folder_id in cur.fetchall()}
            
            print(f"\nExisting clients in database: {len(existing)}")
            print(f"Clients in Google Drive: {len(clients)}")
            print()
            
            new_clients = 0
            new_documents = 0
            updated_clients = 0
            
            for client in clients:
                name = client['name']
                folder_id = client['folder_id']
                created_date = client['created_date'][:19].replace('T', ' ')
                modified_date = client['modified_date'][:19].replace('T', ' ')
                
                # Check if client exists
                if name in existing:
                    # Client exists - check if folder_id matches
                    if existing[name] != folder_id:
                        print(f"⚠️  Updating folder_id for: {name}")
                        cur.execute(
                            "UPDATE clients SET folder_id = ?, updated_at = ? WHERE name = ?",
                            (folder_id, modified_date, name)
                        )
                        updated_clients += 1
                    
                    # Get client_id
                    cur.execute("SELECT id FROM clients WHERE name = ?", (name,))
                    client_id = cur.fetchone()[0]
                else:
                    # New client - insert
                    print(f"➕ Adding new client: {name}")
                    cur.execute(
                        "INSERT INTO clients (name, folder_id, created_at, updated_at) VALUES (?, ?, ?, ?)",
                        (name, folder_id, created_date, modified_date)
                    )
                    client_id = cur.lastrowid
                    new_clients += 1
                
                # Process files in this folder
                for file in client['files']:
                    file_id = file['id']
                    file_name = file['title']
                    file_url = f"https://drive.google.com/uc?export=download&id={file_id}"
                    file_size = int(file.get('fileSize', 0))
                    mime_type = file.get('mimeType', 'application/octet-stream')
                    upload_time = file.get('createdDate', datetime.now().isoformat())[:19].replace('T', ' ')
                    
                    # Determine document type from filename
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
                        # Try to guess from filename pattern
                        parts = file_name.split('_')
                        if len(parts) >= 2:
                            doc_type = parts[1].lower()
                            if doc_type not in ['datasheet', 'aadhaar', 'pan', 'bank_account']:
                                doc_type = 'datasheet'  # Default
                        else:
                            doc_type = 'datasheet'  # Default
                    
                    # Check if document already exists
                    cur.execute("SELECT COUNT(*) FROM documents WHERE file_id = ?", (file_id,))
                    if cur.fetchone()[0] == 0:
                        # Insert document
                        try:
                            cur.execute(
                                """INSERT INTO documents 
                                   (client_id, document_type, file_id, file_name, url, file_size, mime_type, upload_time)
                                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                                (client_id, doc_type, file_id, file_name, file_url, file_size, mime_type, upload_time)
                            )
                            new_documents += 1
                            print(f"   ✓ Added: {file_name} ({doc_type})")
                        except Exception as e:
                            print(f"   ✗ Failed to add {file_name}: {str(e)}")
            
            conn.commit()
            
            print("\n" + "=" * 60)
            print("📊 Sync Summary:")
            print("-" * 60)
            print(f"✅ New clients added: {new_clients}")
            print(f"✅ Clients updated: {updated_clients}")
            print(f"✅ New documents added: {new_documents}")
            print(f"✅ Total clients in DB: {len(existing) + new_clients}")
            print("=" * 60)
            
            return True
            
    except Exception as e:
        print(f"\n❌ Database sync error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


def verify_sync():
    """Verify the sync results"""
    print("\n" + "=" * 60)
    print("🔍 Verification")
    print("=" * 60)
    
    try:
        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()
            
            # Count clients
            cur.execute("SELECT COUNT(*) FROM clients")
            client_count = cur.fetchone()[0]
            
            # Count documents
            cur.execute("SELECT COUNT(*) FROM documents")
            doc_count = cur.fetchone()[0]
            
            # Documents by type
            cur.execute("""
                SELECT document_type, COUNT(*) 
                FROM documents 
                GROUP BY document_type
            """)
            doc_types = cur.fetchall()
            
            # Clients with document counts
            cur.execute("""
                SELECT c.name, COUNT(d.id) as doc_count
                FROM clients c
                LEFT JOIN documents d ON c.id = d.client_id
                GROUP BY c.id
                ORDER BY doc_count DESC
                LIMIT 10
            """)
            top_clients = cur.fetchall()
            
            print(f"\n📊 Database Statistics:")
            print(f"   • Total Clients: {client_count}")
            print(f"   • Total Documents: {doc_count}")
            print(f"\n📄 Documents by Type:")
            for doc_type, count in doc_types:
                print(f"   • {doc_type}: {count}")
            print(f"\n👥 Top 10 Clients by Document Count:")
            for name, count in top_clients:
                print(f"   • {name}: {count} document(s)")
            
    except Exception as e:
        print(f"❌ Verification error: {str(e)}")


def main():
    """Main sync routine"""
    print("=" * 60)
    print("🔄 Google Drive to Database Sync Tool")
    print("=" * 60)
    print()
    print("This will:")
    print("  1. Scan your Google Drive folder")
    print("  2. Find all client folders")
    print("  3. Add missing clients to database")
    print("  4. Add missing documents to database")
    print()
    
    response = input("Continue? (Y/n): ").strip().lower()
    if response == 'n':
        print("❌ Sync cancelled")
        return
    
    # Get root folder ID
    root_folder_id = os.getenv('GOOGLE_DRIVE_FOLDER_ID')
    if not root_folder_id:
        print("❌ GOOGLE_DRIVE_FOLDER_ID not set in .env file!")
        return
    
    print(f"\n📁 Root Folder ID: {root_folder_id}")
    
    # Connect to Drive
    drive = setup_google_drive()
    if not drive:
        return
    
    # Scan Drive
    clients = scan_drive_folders(drive, root_folder_id)
    if not clients:
        print("\n⚠️  No folders found in Drive!")
        return
    
    # Sync to database
    print(f"\n💾 Ready to sync {len(clients)} client(s) to database")
    response = input("Proceed with sync? (Y/n): ").strip().lower()
    if response == 'n':
        print("❌ Sync cancelled")
        return
    
    if sync_to_database(clients):
        verify_sync()
        print("\n✅ Sync complete! Try fetching clients in your web app now.")
    else:
        print("\n❌ Sync failed!")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()