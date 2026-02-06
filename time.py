#!/usr/bin/env python3
"""
Check timezone settings in PostgreSQL vs Python
"""

import os
from datetime import datetime
import psycopg2
from dotenv import load_dotenv

load_dotenv()

def check_timezones():
    print("=" * 60)
    print("  TIMEZONE DIAGNOSTIC")
    print("=" * 60)
    
    # Python system time
    python_now = datetime.now()
    print(f"\n📅 Python System Time:")
    print(f"   {python_now}")
    print(f"   Timezone: {python_now.astimezone().tzname()}")
    
    # PostgreSQL time
    try:
        conn = psycopg2.connect(
            host=os.getenv('DB_HOST'),
            database=os.getenv('DB_NAME'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            port=os.getenv('DB_PORT', 5432)
        )
        cur = conn.cursor()
        
        # Get PostgreSQL current time
        cur.execute("SELECT NOW(), CURRENT_TIMESTAMP, timezone('UTC', NOW())")
        pg_now, pg_timestamp, pg_utc = cur.fetchone()
        
        print(f"\n🐘 PostgreSQL Time:")
        print(f"   NOW(): {pg_now}")
        print(f"   CURRENT_TIMESTAMP: {pg_timestamp}")
        print(f"   UTC: {pg_utc}")
        
        # Get PostgreSQL timezone setting
        cur.execute("SHOW TIMEZONE")
        pg_tz = cur.fetchone()[0]
        print(f"   Database Timezone: {pg_tz}")
        
        # Calculate difference
        if pg_now.tzinfo is None:
            # Naive datetime
            time_diff = (pg_now - python_now).total_seconds()
        else:
            # Timezone-aware
            time_diff = (pg_now.replace(tzinfo=None) - python_now).total_seconds()
        
        print(f"\n⏰ Time Difference:")
        print(f"   PostgreSQL - Python: {time_diff} seconds")
        
        if abs(time_diff) > 60:
            print(f"\n⚠️  WARNING: Large time difference detected!")
            print(f"   This will cause OTP validation issues.")
            print(f"\n   Solutions:")
            print(f"   1. Sync your system clock")
            print(f"   2. Use PostgreSQL's NOW() function instead of Python datetime")
        else:
            print(f"\n✅ Time difference is acceptable (< 1 minute)")
        
        # Check OTP codes
        print("\n" + "=" * 60)
        print("  CHECKING OTP CODES")
        print("=" * 60)
        
        cur.execute("""
            SELECT username, otp_code, 
                   created_at, expires_at, used,
                   EXTRACT(EPOCH FROM (expires_at - NOW())) as seconds_remaining,
                   EXTRACT(EPOCH FROM (NOW() - created_at)) as seconds_old
            FROM otp_codes 
            ORDER BY created_at DESC 
            LIMIT 5
        """)
        
        codes = cur.fetchall()
        
        if codes:
            print("\n📋 Recent OTP Codes:\n")
            for code in codes:
                username, otp, created, expires, used, remaining, age = code
                status = "✓ USED" if used else ("❌ EXPIRED" if remaining <= 0 else f"✅ VALID ({int(remaining)}s left)")
                print(f"User: {username}")
                print(f"OTP:  {otp}")
                print(f"Age:  {int(age)}s old")
                print(f"Remaining: {int(remaining)}s")
                print(f"Status: {status}")
                print("-" * 60)
        else:
            print("\n⚠️  No OTP codes in database")
        
        cur.close()
        conn.close()
        
    except Exception as e:
        print(f"\n❌ Error connecting to PostgreSQL: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    try:
        check_timezones()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user.")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()