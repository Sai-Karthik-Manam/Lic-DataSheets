#!/usr/bin/env python3
"""
Setup script for Lic Agent Datasheets Fetching application.
This script helps configure the environment variables needed for Google OAuth.
"""

import os
import shutil

def main():
    print("🔧 Lic Agent Datasheets Fetching - Setup Script")
    print("=" * 50)
    
    # Check if .env already exists
    if os.path.exists('.env'):
        print("⚠️  .env file already exists!")
        response = input("Do you want to overwrite it? (y/N): ").lower()
        if response != 'y':
            print("Setup cancelled.")
            return
    
    # Copy env.example to .env
    if os.path.exists('env.example'):
        shutil.copy('env.example', '.env')
        print("✅ Created .env file from env.example")
    else:
        print("❌ env.example file not found!")
        return
    
    print("\n📝 Next steps:")
    print("1. Edit the .env file with your Google OAuth credentials")
    print("2. Get credentials from: https://console.cloud.google.com/")
    print("3. Enable Google Drive API and create OAuth 2.0 credentials")
    print("4. Run 'python app.py' to start the application")
    print("\n🔐 Security reminder:")
    print("- Never commit .env files to version control")
    print("- Keep your credentials secure")

if __name__ == "__main__":
    main()
