import os
from dotenv import load_dotenv

load_dotenv()

from app import app

print("\n" + "="*70)
print("🔍 CHECKING CSRF PROTECTION STATUS FOR ALL ROUTES")
print("="*70 + "\n")

exempt_count = 0
protected_count = 0

for rule in app.url_map.iter_rules():
    if rule.endpoint.startswith('static'):
        continue
        
    endpoint = rule.endpoint
    view_func = app.view_functions.get(endpoint)
    
    # Check if route has csrf.exempt
    has_exempt = False
    if view_func:
        has_exempt = getattr(view_func, '_csrf_exempt', False)
    
    methods = ','.join(rule.methods - {'OPTIONS', 'HEAD'})
    
    if has_exempt:
        status = "❌ EXEMPT (No CSRF Protection)"
        exempt_count += 1
        icon = "⚠️"
    else:
        status = "✅ PROTECTED (CSRF Enabled)"
        protected_count += 1
        icon = "🔒"
    
    print(f"{icon} {rule.rule:45} [{methods:10}] {status}")

print("\n" + "="*70)
print(f"📊 SUMMARY")
print("="*70)
print(f"✅ Protected Routes (CSRF Enabled):  {protected_count}")
print(f"⚠️  Exempt Routes (No CSRF):         {exempt_count}")
print(f"📍 Focus on:                        /fetch_data route")
print("="*70 + "\n")

# Specifically check fetch_data
print("🎯 CHECKING FETCH_DATA ROUTE SPECIFICALLY:\n")

fetch_data_view = app.view_functions.get('fetch_data')
if fetch_data_view:
    has_exempt = getattr(fetch_data_view, '_csrf_exempt', False)
    print(f"Route: /fetch_data")
    print(f"CSRF Exempt: {has_exempt}")
    print(f"Status: {'❌ CSRF DISABLED!' if has_exempt else '✅ CSRF ENABLED'}")
    
    if has_exempt:
        print("\n⚠️  PROBLEM FOUND:")
        print("   The /fetch_data route has @csrf.exempt decorator!")
        print("   This disables CSRF protection on this route.")
        print("\n✅ SOLUTION:")
        print("   1. Open app.py")
        print("   2. Find the @fetch_data route definition")
        print("   3. Remove the @csrf.exempt line if it exists")
        print("   4. Save and restart Flask")
else:
    print("❌ fetch_data route not found!")

print("\n" + "="*70)