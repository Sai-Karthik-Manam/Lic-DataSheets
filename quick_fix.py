#!/usr/bin/env python3
"""
Quick fix script to resolve common issues
"""

import os
import sys

def check_env_file():
    """Check if .env file exists and has required variables"""
    if not os.path.exists('.env'):
        print("❌ .env file not found!")
        print("   Please create .env file with your Google OAuth credentials")
        return False
    
    print("✅ .env file exists")
    
    # Check for required variables
    from dotenv import load_dotenv
    load_dotenv()
    
    required_vars = ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET']
    missing = []
    
    for var in required_vars:
        if not os.getenv(var):
            missing.append(var)
    
    if missing:
        print(f"❌ Missing required environment variables: {', '.join(missing)}")
        return False
    
    print("✅ Required environment variables are set")
    
    if not os.getenv('GOOGLE_REFRESH_TOKEN'):
        print("⚠️  GOOGLE_REFRESH_TOKEN is not set")
        print("   The app will prompt for OAuth authentication on first run")
    else:
        print("✅ GOOGLE_REFRESH_TOKEN is set")
    
    return True


def check_client_secrets():
    """Check if client_secrets.json exists"""
    if os.path.exists('client_secrets.json'):
        print("⚠️  client_secrets.json exists")
        response = input("   Delete it? (Y/n): ").strip().lower()
        if response != 'n':
            try:
                os.remove('client_secrets.json')
                print("✅ Deleted client_secrets.json (will be regenerated from .env)")
            except Exception as e:
                print(f"❌ Could not delete: {e}")
                return False
    else:
        print("✅ client_secrets.json does not exist (good)")
    
    return True


def check_database():
    """Check database and offer to migrate"""
    if not os.path.exists('database.db'):
        print("ℹ️  database.db does not exist (will be created on first run)")
        return True
    
    print("✅ database.db exists")
    
    import sqlite3
    try:
        with sqlite3.connect('database.db') as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(datasheets)")
            columns = [column[1] for column in cursor.fetchall()]
            
            missing_cols = []
            if 'file_size' not in columns:
                missing_cols.append('file_size')
            if 'mime_type' not in columns:
                missing_cols.append('mime_type')
            
            if missing_cols:
                print(f"⚠️  Missing columns: {', '.join(missing_cols)}")
                response = input("   Run database migration now? (Y/n): ").strip().lower()
                if response != 'n':
                    # Run migration inline
                    if 'file_size' not in columns:
                        cursor.execute("ALTER TABLE datasheets ADD COLUMN file_size INTEGER")
                        print("✅ Added file_size column")
                    if 'mime_type' not in columns:
                        cursor.execute("ALTER TABLE datasheets ADD COLUMN mime_type TEXT")
                        print("✅ Added mime_type column")
                    conn.commit()
                    print("✅ Database migration completed")
            else:
                print("✅ All required columns exist")
    
    except Exception as e:
        print(f"❌ Database check failed: {e}")
        return False
    
    return True


def check_dependencies():
    """Check if required packages are installed"""
    # Map of package names to their import names
    required_packages = {
        'flask': 'flask',
        'pydrive2': 'pydrive2',
        'python-dotenv': 'dotenv',
        'oauth2client': 'oauth2client'
    }
    
    missing = []
    for package, import_name in required_packages.items():
        try:
            __import__(import_name)
        except ImportError:
            missing.append(package)
    
    if missing:
        print(f"❌ Missing packages: {', '.join(missing)}")
        print("   Install with: pip install -r requirements.txt")
        return False
    
    print("✅ All required packages are installed")
    return True


def main():
    print("=" * 60)
    print("LIC Datasheet App - Quick Fix Script")
    print("=" * 60)
    print()
    
    all_good = True
    
    print("🔍 Checking dependencies...")
    if not check_dependencies():
        all_good = False
    print()
    
    print("🔍 Checking environment variables...")
    if not check_env_file():
        all_good = False
    print()
    
    print("🔍 Checking client_secrets.json...")
    if not check_client_secrets():
        all_good = False
    print()
    
    print("🔍 Checking database...")
    if not check_database():
        all_good = False
    print()
    
    print("=" * 60)
    if all_good:
        print("✅ All checks passed! You can run the app with:")
        print("   python app.py")
        print()
        print("⚠️  If you still see OAuth errors, you need to:")
        print("   1. Delete old credentials in Google Cloud Console")
        print("   2. Create new OAuth credentials")
        print("   3. Update .env with new CLIENT_ID and CLIENT_SECRET")
        print()
        print("   See FIX_CREDENTIALS.md for detailed instructions")
    else:
        print("❌ Some issues need to be fixed before running the app")
        print("   Please address the errors above")
    print("=" * 60)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Script interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)