import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

print("=" * 60)
print("🔍 CSRF & Environment Debug Report")
print("=" * 60)

# Check SECRET_KEY
secret_key = os.getenv('SECRET_KEY')
print(f"\n✅ SECRET_KEY Status:")
print(f"   - Exists: {bool(secret_key)}")
print(f"   - Length: {len(secret_key) if secret_key else 0} characters")
print(f"   - Value (first 20 chars): {secret_key[:20] if secret_key else 'NOT SET'}...")

# Check other required variables
print(f"\n✅ Google Drive Configuration:")
print(f"   - GOOGLE_DRIVE_FOLDER_ID: {bool(os.getenv('GOOGLE_DRIVE_FOLDER_ID'))}")
print(f"   - GOOGLE_CLIENT_ID: {bool(os.getenv('GOOGLE_CLIENT_ID'))}")
print(f"   - GOOGLE_CLIENT_SECRET: {bool(os.getenv('GOOGLE_CLIENT_SECRET'))}")
print(f"   - GOOGLE_REFRESH_TOKEN: {bool(os.getenv('GOOGLE_REFRESH_TOKEN'))}")

# Check Database Configuration
print(f"\n✅ Database Configuration:")
print(f"   - DB_HOST: {os.getenv('DB_HOST', 'Not set (using SQLite)')}")
print(f"   - DB_NAME: {os.getenv('DB_NAME', 'Not set')}")
print(f"   - Using PostgreSQL: {bool(os.getenv('DB_HOST'))}")

# Check Flask Configuration
print(f"\n✅ Flask Configuration:")
print(f"   - FLASK_DEBUG: {os.getenv('FLASK_DEBUG', 'False')}")
print(f"   - PORT: {os.getenv('PORT', '5000')}")

# Now test with app context
print(f"\n" + "=" * 60)
print("Testing Flask App Context...")
print("=" * 60)

try:
    from app import app, csrf
    
    with app.app_context():
        secret_key = app.config.get('SECRET_KEY')
        print(f"\n✅ Flask App Loaded Successfully!")
        print(f"   - SECRET_KEY configured: {bool(secret_key)}")
        print(f"   - CSRF Protection: {csrf}")
        print(f"   - App Debug Mode: {app.debug}")
        
        # Test CSRF token generation
        from flask_wtf.csrf import generate_csrf
        token = generate_csrf()
        print(f"   - CSRF Token Generated: {bool(token)}")
        print(f"   - Token Length: {len(token)} characters")
        print(f"   - Token (first 30 chars): {token[:30]}...")
        
        print(f"\n✅ ALL SYSTEMS OPERATIONAL! ✓")
        
except ValueError as e:
    print(f"\n❌ ERROR: {str(e)}")
    print(f"\n⚠️  SOLUTION: Set the missing environment variable!")
    print(f"   Add to your .env file:")
    print(f"   SECRET_KEY=your-random-secret-key")
    print(f"\n   Generate one with:")
    print(f"   python -c \"import secrets; print(secrets.token_urlsafe(32))\"")
    
except Exception as e:
    print(f"\n❌ ERROR: {str(e)}")
    print(f"   Type: {type(e).__name__}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 60)