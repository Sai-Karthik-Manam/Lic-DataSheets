#!/usr/bin/env python3
"""
Verify that OTP functions use PostgreSQL NOW() for timezone handling
"""

import os
import re

def check_app_py():
    print("=" * 60)
    print("  CHECKING app.py FOR TIMEZONE FIX")
    print("=" * 60)
    
    if not os.path.exists('app.py'):
        print("\n❌ app.py not found!")
        return
    
    with open('app.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check store_otp function
    print("\n📋 Checking store_otp function...")
    
    if "NOW() + INTERVAL '5 minutes'" in content:
        print("✅ store_otp uses PostgreSQL NOW() - CORRECT")
    else:
        print("❌ store_otp does NOT use PostgreSQL NOW() - NEEDS FIX")
        print("   Looking for: NOW() + INTERVAL '5 minutes'")
    
    # Check verify_otp function
    print("\n📋 Checking verify_otp function...")
    
    if "EXTRACT(EPOCH FROM (expires_at - NOW()))" in content:
        print("✅ verify_otp uses PostgreSQL NOW() - CORRECT")
    else:
        print("❌ verify_otp does NOT use PostgreSQL NOW() - NEEDS FIX")
        print("   Looking for: EXTRACT(EPOCH FROM (expires_at - NOW()))")
    
    # Check for old problematic code
    print("\n📋 Checking for old problematic code...")
    
    problematic_patterns = [
        ("datetime.now()", "Should use PostgreSQL NOW() instead"),
        ("timedelta(minutes=5)", "Should use INTERVAL '5 minutes' instead"),
    ]
    
    issues_found = False
    for pattern, reason in problematic_patterns:
        # Only check in OTP-related functions
        if pattern in content:
            # Find context
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if pattern in line and ('store_otp' in '\n'.join(lines[max(0,i-10):i+10]) or 
                                       'verify_otp' in '\n'.join(lines[max(0,i-10):i+10])):
                    print(f"⚠️  Found: {pattern}")
                    print(f"   Reason: {reason}")
                    print(f"   Line {i+1}: {line.strip()[:80]}")
                    issues_found = True
    
    if not issues_found:
        print("✅ No problematic datetime code found in OTP functions")
    
    print("\n" + "=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    
    has_now_interval = "NOW() + INTERVAL '5 minutes'" in content
    has_extract_epoch = "EXTRACT(EPOCH FROM (expires_at - NOW()))" in content
    
    if has_now_interval and has_extract_epoch:
        print("\n✅ app.py appears to have the timezone fix!")
        print("\n📝 Your OTP functions should work correctly.")
        print("\nIf OTP still fails, try:")
        print("1. Restart the Flask app")
        print("2. Clear old OTP codes from database")
        print("3. Test login with fresh OTP")
    else:
        print("\n❌ app.py NEEDS the timezone fix!")
        print("\n📝 You need to replace store_otp and verify_otp functions")
        print("   with the timezone-fixed versions.")
        print("\nSee the artifact: 'Complete Timezone Fix for app.py'")

if __name__ == "__main__":
    try:
        check_app_py()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user.")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()