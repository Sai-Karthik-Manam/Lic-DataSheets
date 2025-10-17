#!/usr/bin/env python3
"""
Diagnostic script to check database and fix client data issues
"""

import sqlite3
from datetime import datetime

def diagnose_database():
    """Check what's in the database"""
    print("=" * 60)
    print("🔍 LIC Manager - Database Diagnostic")
    print("=" * 60)
    print()
    
    try:
        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()
            
            # Check clients table
            print("📋 CLIENTS TABLE:")
            print("-" * 60)
            cur.execute("SELECT id, name, folder_id, created_at FROM clients")
            clients = cur.fetchall()
            
            if clients:
                print(f"Found {len(clients)} client(s):\n")
                for i, (id, name, folder_id, created_at) in enumerate(clients, 1):
                    print(f"{i}. ID: {id}")
                    print(f"   Name: '{name}'")
                    print(f"   Name Length: {len(name)} characters")
                    print(f"   Folder ID: {folder_id}")
                    print(f"   Created: {created_at}")
                    print(f"   Name Bytes: {name.encode('utf-8')}")
                    print()
            else:
                print("❌ No clients found in database!")
                print()
            
            # Check documents table
            print("📄 DOCUMENTS TABLE:")
            print("-" * 60)
            cur.execute("""
                SELECT d.id, c.name, d.document_type, d.file_name, d.upload_time
                FROM documents d
                JOIN clients c ON d.client_id = c.id
                ORDER BY c.name, d.document_type
            """)
            documents = cur.fetchall()
            
            if documents:
                print(f"Found {len(documents)} document(s):\n")
                current_client = None
                for doc_id, client_name, doc_type, file_name, upload_time in documents:
                    if client_name != current_client:
                        print(f"\n👤 Client: {client_name}")
                        current_client = client_name
                    print(f"   • {doc_type}: {file_name} ({upload_time})")
            else:
                print("❌ No documents found in database!")
            print()
            
            # Check for orphaned documents
            print("🔍 CHECKING FOR ISSUES:")
            print("-" * 60)
            
            # Check for documents without clients
            cur.execute("""
                SELECT COUNT(*) FROM documents 
                WHERE client_id NOT IN (SELECT id FROM clients)
            """)
            orphaned = cur.fetchone()[0]
            if orphaned > 0:
                print(f"⚠️  Found {orphaned} orphaned document(s) (no matching client)")
            else:
                print("✅ No orphaned documents")
            
            # Check for duplicate client names
            cur.execute("""
                SELECT name, COUNT(*) as count 
                FROM clients 
                GROUP BY name 
                HAVING count > 1
            """)
            duplicates = cur.fetchall()
            if duplicates:
                print(f"⚠️  Found duplicate client names:")
                for name, count in duplicates:
                    print(f"   • '{name}' appears {count} times")
            else:
                print("✅ No duplicate client names")
            
            # Check for clients without documents
            cur.execute("""
                SELECT c.id, c.name 
                FROM clients c
                LEFT JOIN documents d ON c.id = d.client_id
                WHERE d.id IS NULL
            """)
            empty_clients = cur.fetchall()
            if empty_clients:
                print(f"⚠️  Found {len(empty_clients)} client(s) without documents:")
                for cid, name in empty_clients:
                    print(f"   • ID {cid}: '{name}'")
            else:
                print("✅ All clients have documents")
            
            print()
            
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()


def fix_database():
    """Interactive fix for common issues"""
    print("\n" + "=" * 60)
    print("🔧 DATABASE FIX OPTIONS")
    print("=" * 60)
    print()
    print("1. Remove orphaned documents")
    print("2. Remove empty clients (no documents)")
    print("3. Trim whitespace from client names")
    print("4. Show all client names for testing")
    print("5. Add missing folder IDs")
    print("6. Exit")
    print()
    
    choice = input("Choose an option (1-6): ").strip()
    
    try:
        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()
            
            if choice == '1':
                # Remove orphaned documents
                cur.execute("""
                    DELETE FROM documents 
                    WHERE client_id NOT IN (SELECT id FROM clients)
                """)
                deleted = cur.rowcount
                conn.commit()
                print(f"✅ Removed {deleted} orphaned document(s)")
            
            elif choice == '2':
                # Remove empty clients
                cur.execute("""
                    DELETE FROM clients 
                    WHERE id NOT IN (SELECT DISTINCT client_id FROM documents)
                """)
                deleted = cur.rowcount
                conn.commit()
                print(f"✅ Removed {deleted} empty client(s)")
            
            elif choice == '3':
                # Trim whitespace
                cur.execute("SELECT id, name FROM clients")
                clients = cur.fetchall()
                fixed = 0
                for cid, name in clients:
                    trimmed = name.strip()
                    if trimmed != name:
                        cur.execute("UPDATE clients SET name = ? WHERE id = ?", (trimmed, cid))
                        fixed += 1
                        print(f"Fixed: '{name}' -> '{trimmed}'")
                conn.commit()
                print(f"✅ Fixed {fixed} client name(s)")
            
            elif choice == '4':
                # Show all names
                cur.execute("SELECT name FROM clients ORDER BY name")
                clients = cur.fetchall()
                print("\n📋 All client names in database:")
                print("-" * 60)
                for i, (name,) in enumerate(clients, 1):
                    print(f"{i}. '{name}' (length: {len(name)})")
                print("\n💡 Try searching with these exact names")
            
            elif choice == '5':
                # Add missing folder IDs
                cur.execute("SELECT id, name FROM clients WHERE folder_id IS NULL OR folder_id = ''")
                clients = cur.fetchall()
                if clients:
                    print(f"\n⚠️  Found {len(clients)} client(s) with missing folder IDs")
                    for cid, name in clients:
                        # Generate a placeholder folder ID
                        placeholder = f"placeholder_{cid}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
                        cur.execute("UPDATE clients SET folder_id = ? WHERE id = ?", (placeholder, cid))
                        print(f"Added placeholder folder ID for: {name}")
                    conn.commit()
                    print("\n✅ Fixed! Note: These will be replaced when you upload new documents")
                else:
                    print("✅ All clients have folder IDs")
            
            elif choice == '6':
                return False
            
            else:
                print("❌ Invalid choice")
            
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
    
    return True


def test_search():
    """Test search functionality"""
    print("\n" + "=" * 60)
    print("🔍 TEST SEARCH")
    print("=" * 60)
    
    search_term = input("\nEnter client name to search: ").strip()
    
    if not search_term:
        print("❌ Please enter a name")
        return
    
    try:
        with sqlite3.connect("database.db") as conn:
            cur = conn.cursor()
            
            # Exact match
            cur.execute("SELECT id, name FROM clients WHERE name = ?", (search_term,))
            exact = cur.fetchone()
            
            # Case-insensitive match
            cur.execute("SELECT id, name FROM clients WHERE LOWER(name) = LOWER(?)", (search_term,))
            case_insensitive = cur.fetchone()
            
            # Partial match
            cur.execute("SELECT id, name FROM clients WHERE name LIKE ?", (f'%{search_term}%',))
            partial = cur.fetchall()
            
            print(f"\nSearching for: '{search_term}'")
            print("-" * 60)
            print(f"Exact match: {'✅ Found: ' + exact[1] if exact else '❌ Not found'}")
            print(f"Case-insensitive: {'✅ Found: ' + case_insensitive[1] if case_insensitive else '❌ Not found'}")
            print(f"Partial matches: {len(partial)} found")
            
            if partial:
                print("\nPartial matches:")
                for cid, name in partial:
                    print(f"  • ID {cid}: '{name}'")
            
            # Show documents if found
            if exact or case_insensitive:
                client_id = exact[0] if exact else case_insensitive[0]
                cur.execute("""
                    SELECT document_type, file_name 
                    FROM documents 
                    WHERE client_id = ?
                """, (client_id,))
                docs = cur.fetchall()
                
                if docs:
                    print(f"\n📄 Documents for this client:")
                    for doc_type, file_name in docs:
                        print(f"  • {doc_type}: {file_name}")
                else:
                    print(f"\n⚠️  Client found but no documents!")
            
    except Exception as e:
        print(f"❌ Error: {str(e)}")


def main():
    """Main diagnostic routine"""
    while True:
        diagnose_database()
        
        print("\n" + "=" * 60)
        print("WHAT WOULD YOU LIKE TO DO?")
        print("=" * 60)
        print("1. Run fixes")
        print("2. Test search")
        print("3. Re-run diagnostic")
        print("4. Exit")
        print()
        
        choice = input("Choose (1-4): ").strip()
        
        if choice == '1':
            while fix_database():
                print("\n" + "-" * 60)
                if input("Apply another fix? (y/n): ").lower() != 'y':
                    break
        elif choice == '2':
            test_search()
        elif choice == '3':
            continue
        elif choice == '4':
            print("\n✅ Diagnostic complete!")
            break
        else:
            print("❌ Invalid choice")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()