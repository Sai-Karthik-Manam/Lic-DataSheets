#!/usr/bin/env python3
"""
Clear all old OTP codes from database
"""

import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()

def clear_otps():
    print("=" * 60)
    print("  CLEAR OLD OTP CODES")
    print("=" * 60)
    
    conn = psycopg2.connect(
        host=os.getenv('DB_HOST'),
        database=os.getenv('DB_NAME'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD'),
        port=os.getenv('DB_PORT', 5432)
    )
    cur = conn.cursor()
    
    try:
        # Count existing OTPs
        cur.execute("SELECT COUNT(*) FROM otp_codes")
        total = cur.fetchone()[0]
        
        print(f"\n📊 Current OTP codes in database: {total}")
        
        if total == 0:
            print("\n✅ No OTP codes to clear")
            return
        
        # Show breakdown
        cur.execute("""
            SELECT username, COUNT(*) 
            FROM otp_codes 
            GROUP BY username
        """)
        
        breakdown = cur.fetchall()
        print("\n📋 Breakdown by user:")
        for username, count in breakdown:
            print(f"  • {username}: {count} OTP(s)")
        
        response = input(f"\nDelete all {total} OTP codes? (yes/no): ").strip().lower()
        
        if response != 'yes':
            print("❌ Cancelled")
            return
        
        # Delete all OTPs
        cur.execute("DELETE FROM otp_codes")
        deleted = cur.rowcount
        conn.commit()
        
        print(f"\n✅ Deleted {deleted} OTP code(s)")
        print("\n" + "=" * 60)
        print("  ✅ CLEANUP COMPLETE!")
        print("=" * 60)
        print("\nNext steps:")
        print("1. Restart your Flask app: python app.py")
        print("2. Login with karthik or veerababu")
        print("3. Fresh OTP will be generated with correct timezone")
        
    except Exception as e:
        conn.rollback()
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    try:
        clear_otps()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user.")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()