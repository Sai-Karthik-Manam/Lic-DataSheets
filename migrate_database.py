#!/usr/bin/env python3
"""
Database migration script for multi-document system
This migrates from the old single-file system to the new multi-document system
"""

import sqlite3
import os
from datetime import datetime

def backup_database():
    """Create a backup of the database before migration"""
    db_file = "database.db"
    backup_file = f"database_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
    
    if not os.path.exists(db_file):
        return None
    
    try:
        import shutil
        shutil.copy2(db_file, backup_file)
        print(f"✅ Database backed up to {backup_file}")
        return backup_file
    except Exception as e:
        print(f"⚠️  Warning: Could not create backup: {str(e)}")
        return None


def migrate_database():
    """Migrate from old schema to new multi-document schema"""
    
    db_file = "database.db"
    
    if not os.path.exists(db_file):
        print("❌ Database file not found. Creating new database...")
        # New database will be created by app.py
        return True
    
    print("🔄 Starting database migration to multi-document system...")
    
    try:
        with sqlite3.connect(db_file) as conn:
            cursor = conn.cursor()
            
            # Check if old table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='datasheets'")
            old_table_exists = cursor.fetchone() is not None
            
            # Check if new tables exist
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='clients'")
            clients_exists = cursor.fetchone() is not None
            
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='documents'")
            documents_exists = cursor.fetchone() is not None
            
            if clients_exists and documents_exists:
                print("✅ New schema already exists. No migration needed.")
                return True
            
            if not old_table_exists:
                print("ℹ️  No old data to migrate. New tables will be created by app.py")
                return True
            
            print("📊 Old schema detected. Migrating data...")
            
            # Create new tables
            print("➕ Creating new tables...")
            
            cursor.execute('''CREATE TABLE IF NOT EXISTS clients (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                name TEXT NOT NULL UNIQUE,
                                folder_id TEXT NOT NULL UNIQUE,
                                created_at TEXT NOT NULL,
                                updated_at TEXT NOT NULL
                            )''')
            
            cursor.execute('''CREATE TABLE IF NOT EXISTS documents (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                client_id INTEGER NOT NULL,
                                document_type TEXT NOT NULL,
                                file_id TEXT NOT NULL UNIQUE,
                                file_name TEXT NOT NULL,
                                url TEXT NOT NULL,
                                file_size INTEGER,
                                mime_type TEXT,
                                upload_time TEXT NOT NULL,
                                FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE,
                                UNIQUE(client_id, document_type)
                            )''')
            
            # Create indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_client_name ON clients(name)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_client_id ON documents(client_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_doc_type ON documents(document_type)')
            
            print("✅ New tables created")
            
            # Migrate old data
            print("📦 Migrating old data...")
            
            cursor.execute("SELECT name, file_id, url, upload_time, file_size, mime_type FROM datasheets")
            old_records = cursor.fetchall()
            
            migrated = 0
            errors = 0
            
            for record in old_records:
                name, file_id, url, upload_time, file_size, mime_type = record
                
                try:
                    # Note: We don't have folder_id from old system, will be created when needed
                    # For now, use a placeholder
                    placeholder_folder = "migrate_placeholder"
                    
                    # Insert or get client
                    cursor.execute(
                        "INSERT OR IGNORE INTO clients (name, folder_id, created_at, updated_at) VALUES (?, ?, ?, ?)",
                        (name, f"{placeholder_folder}_{name}", upload_time, upload_time)
                    )
                    
                    cursor.execute("SELECT id FROM clients WHERE name = ?", (name,))
                    client_id = cursor.fetchone()[0]
                    
                    # Insert document as datasheet (the old system only had datasheets)
                    cursor.execute(
                        """INSERT OR IGNORE INTO documents 
                           (client_id, document_type, file_id, file_name, url, file_size, mime_type, upload_time) 
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                        (client_id, 'datasheet', file_id, f"{name}_datasheet", url, 
                         file_size, mime_type, upload_time)
                    )
                    
                    migrated += 1
                    print(f"  ✓ Migrated: {name}")
                    
                except Exception as e:
                    errors += 1
                    print(f"  ✗ Error migrating {name}: {str(e)}")
            
            conn.commit()
            
            print(f"\n📊 Migration Summary:")
            print(f"  • Total records: {len(old_records)}")
            print(f"  • Successfully migrated: {migrated}")
            print(f"  • Errors: {errors}")
            
            # Optionally rename old table
            response = input("\n❓ Rename old 'datasheets' table to 'datasheets_old'? (Y/n): ").strip().lower()
            if response != 'n':
                cursor.execute("ALTER TABLE datasheets RENAME TO datasheets_old")
                print("✅ Old table renamed to 'datasheets_old'")
                print("   You can delete it manually later if everything works fine")
            
            conn.commit()
            
        print("\n✅ Database migration completed successfully!")
        print("⚠️  IMPORTANT: Update folder_id values in Google Drive")
        print("   The first time you upload a document for migrated clients,")
        print("   a new folder will be created and the folder_id will be updated.")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Migration failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


def verify_migration():
    """Verify the migration was successful"""
    print("\n🔍 Verifying migration...")
    
    try:
        with sqlite3.connect("database.db") as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM clients")
            clients_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM documents")
            docs_count = cursor.fetchone()[0]
            
            print(f"✅ Found {clients_count} clients")
            print(f"✅ Found {docs_count} documents")
            
            cursor.execute("""
                SELECT c.name, COUNT(d.id) as doc_count
                FROM clients c
                LEFT JOIN documents d ON c.id = d.client_id
                GROUP BY c.id
                LIMIT 5
            """)
            
            print("\n📋 Sample data:")
            for row in cursor.fetchall():
                print(f"  • {row[0]}: {row[1]} document(s)")
            
        return True
        
    except Exception as e:
        print(f"❌ Verification failed: {str(e)}")
        return False


if __name__ == "__main__":
    print("=" * 60)
    print("LIC Datasheet Manager - Database Migration")
    print("Multi-Document System Upgrade")
    print("=" * 60)
    print()
    
    response = input("⚠️  This will modify your database. Continue? (Y/n): ").strip().lower()
    if response == 'n':
        print("Migration cancelled.")
        exit(0)
    
    print()
    
    # Backup
    backup_file = backup_database()
    print()
    
    # Migrate
    if migrate_database():
        print()
        verify_migration()
        print("\n" + "=" * 60)
        print("✅ All done! You can now run your Flask app.")
        if backup_file:
            print(f"💾 Backup saved at: {backup_file}")
        print("=" * 60)
    else:
        print("\n" + "=" * 60)
        print("❌ Migration failed. Please check errors above.")
        if backup_file:
            print(f"💾 Your original database is backed up at: {backup_file}")
        print("=" * 60)
        exit(1)