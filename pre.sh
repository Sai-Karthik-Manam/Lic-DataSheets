#!/bin/bash

# Pre-Deployment Script for LIC Manager
# Run this before deploying to production

set -e  # Exit on error

echo "======================================"
echo "  LIC Manager Pre-Deployment Script"
echo "======================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to check if file exists
check_file() {
    if [ -f "$1" ]; then
        echo -e "${GREEN}✓${NC} Found: $1"
        return 0
    else
        echo -e "${RED}✗${NC} Missing: $1"
        return 1
    fi
}

# Function to delete file
delete_file() {
    if [ -f "$1" ]; then
        rm "$1"
        echo -e "${GREEN}✓${NC} Deleted: $1"
    else
        echo -e "${YELLOW}⚠${NC}  Not found: $1"
    fi
}

# 1. Check essential files
echo "1. Checking essential files..."
check_file "app.py" || exit 1
check_file "requirements.txt" || exit 1
check_file ".gitignore" || exit 1
check_file "Procfile" || { mv procfile Procfile 2>/dev/null && echo "✓ Renamed procfile to Procfile"; } || echo "⚠ Procfile missing"
echo ""

# 2. Delete unnecessary files
echo "2. Deleting unnecessary files..."
delete_file "app.py.backup"
delete_file "client_secrets.json"
delete_file "temp_client_secrets.json"
delete_file "templates/forgot_password.html"
delete_file "database.db"  # Don't deploy with local SQLite
echo ""

# 3. Check .gitignore
echo "3. Verifying .gitignore..."
if grep -q ".env" .gitignore; then
    echo -e "${GREEN}✓${NC} .env is in .gitignore"
else
    echo -e "${RED}✗${NC} .env is NOT in .gitignore!"
    echo ".env" >> .gitignore
    echo -e "${GREEN}✓${NC} Added .env to .gitignore"
fi

if grep -q "*.json" .gitignore; then
    echo -e "${GREEN}✓${NC} *.json is in .gitignore"
else
    echo -e "${YELLOW}⚠${NC}  *.json is NOT in .gitignore"
    echo "*.json" >> .gitignore
    echo -e "${GREEN}✓${NC} Added *.json to .gitignore"
fi
echo ""

# 4. Check environment variables
echo "4. Checking environment variables..."
if [ -f ".env" ]; then
    echo -e "${YELLOW}⚠${NC}  .env file found! DON'T COMMIT THIS!"
    
    # Check for default passwords
    if grep -q "Admin@123" .env; then
        echo -e "${RED}✗${NC} CRITICAL: Default admin password found in .env!"
    fi
    
    if grep -q "User@123" .env; then
        echo -e "${RED}✗${NC} CRITICAL: Default user password found in .env!"
    fi
    
    # Check for exposed credentials
    if grep -q "GOCSPX-" .env; then
        echo -e "${RED}✗${NC} CRITICAL: Google credentials may be exposed!"
    fi
else
    echo -e "${GREEN}✓${NC} No .env file (good for deployment)"
fi
echo ""

# 5. Check for exposed secrets in code
echo "5. Scanning for hardcoded secrets..."
if grep -r "GOCSPX-" --include="*.py" --include="*.html" .; then
    echo -e "${RED}✗${NC} CRITICAL: Found hardcoded Google secrets!"
else
    echo -e "${GREEN}✓${NC} No hardcoded Google secrets found"
fi

if grep -r "Admin@123" --include="*.py" --include="*.html" .; then
    echo -e "${RED}✗${NC} CRITICAL: Found hardcoded admin password!"
else
    echo -e "${GREEN}✓${NC} No hardcoded admin password found"
fi
echo ""

# 6. Verify Python version
echo "6. Checking Python version..."
if [ -f "runtime.txt" ]; then
    PYTHON_VERSION=$(cat runtime.txt)
    echo "   runtime.txt specifies: $PYTHON_VERSION"
    
    if [[ $PYTHON_VERSION == "python-3.11."* ]]; then
        echo -e "${GREEN}✓${NC} Python 3.11.x (good)"
    else
        echo -e "${YELLOW}⚠${NC}  Consider upgrading to Python 3.11.x"
    fi
else
    echo -e "${YELLOW}⚠${NC}  runtime.txt not found"
    echo "python-3.11.8" > runtime.txt
    echo -e "${GREEN}✓${NC} Created runtime.txt with Python 3.11.8"
fi
echo ""

# 7. Check requirements.txt
echo "7. Checking requirements.txt..."
if grep -q "Flask==" requirements.txt; then
    echo -e "${GREEN}✓${NC} Flask found in requirements.txt"
else
    echo -e "${RED}✗${NC} Flask not found in requirements.txt!"
fi

if grep -q "gunicorn" requirements.txt; then
    echo -e "${GREEN}✓${NC} gunicorn found (good for production)"
else
    echo -e "${YELLOW}⚠${NC}  gunicorn not found - add for production"
fi

if grep -q "bleach" requirements.txt; then
    echo -e "${GREEN}✓${NC} bleach found (input sanitization)"
else
    echo -e "${YELLOW}⚠${NC}  bleach not found - add for security"
fi
echo ""

# 8. Create backup directory
echo "8. Creating backups directory..."
mkdir -p backups
echo -e "${GREEN}✓${NC} backups/ directory ready"
echo ""

# 9. Check Procfile
echo "9. Checking Procfile..."
if [ -f "Procfile" ]; then
    if grep -q "gunicorn" Procfile; then
        echo -e "${GREEN}✓${NC} Procfile uses gunicorn"
    else
        echo -e "${YELLOW}⚠${NC}  Procfile doesn't use gunicorn"
    fi
else
    echo -e "${RED}✗${NC} Procfile not found!"
    echo "web: gunicorn app:app" > Procfile
    echo -e "${GREEN}✓${NC} Created Procfile"
fi
echo ""

# 10. Final warnings
echo "======================================"
echo "  Pre-Deployment Checklist"
echo "======================================"
echo ""
echo -e "${YELLOW}BEFORE DEPLOYING:${NC}"
echo "  1. ❌ Delete or regenerate ALL credentials in .env"
echo "  2. ❌ Set environment variables in hosting platform"
echo "  3. ❌ Never commit .env file"
echo "  4. ❌ Change SECRET_KEY"
echo "  5. ❌ Change database password"
echo "  6. ❌ Regenerate Google OAuth credentials"
echo "  7. ❌ Regenerate SMTP app password"
echo "  8. ✅ Set FLASK_ENV=production"
echo "  9. ✅ Set FLASK_DEBUG=False"
echo " 10. ✅ Enable HTTPS"
echo ""
echo -e "${RED}⚠️  CRITICAL: Your current credentials are EXPOSED in the files!${NC}"
echo -e "${RED}⚠️  You MUST regenerate all credentials before deploying!${NC}"
echo ""

# 11. Generate new secret key
echo "======================================"
echo "  Generate New Credentials"
echo "======================================"
echo ""
echo "New SECRET_KEY (copy this):"
python3 -c "import secrets; print(secrets.token_urlsafe(64))" || python -c "import secrets; print(secrets.token_urlsafe(64))"
echo ""
echo "Copy this key and set it as SECRET_KEY environment variable"
echo ""

# 12. Summary
echo "======================================"
echo "  Summary"
echo "======================================"
echo ""
echo "✓ Unnecessary files deleted"
echo "✓ .gitignore updated"
echo "✓ Procfile verified"
echo "✓ New SECRET_KEY generated"
echo ""
echo -e "${GREEN}Ready for manual credential update!${NC}"
echo ""
echo "Next steps:"
echo "  1. Go to Google Cloud Console and create NEW OAuth credentials"
echo "  2. Change your database password"
echo "  3. Generate new Gmail app password"
echo "  4. Set all environment variables in your hosting platform"
echo "  5. Deploy!"
echo ""