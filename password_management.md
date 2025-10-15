# 🔐 Password Management Guide

## 🎯 How to Change Your Password

### **Method 1: Via Web Interface** ⭐ (Recommended)

1. **Login** to your account
2. Click **"🔑 Password"** in the top-right navbar
3. Fill in the form:
   - **Current Password:** Your existing password
   - **New Password:** Enter new password (min 6 characters)
   - **Confirm Password:** Re-enter new password
4. Click **"🔄 Change Password"**
5. You'll be **logged out automatically**
6. **Login again** with your new password

**Features:**
- ✅ Password strength indicator
- ✅ Real-time validation
- ✅ Secure hashing (bcrypt)
- ✅ Activity logging
- ✅ Auto-logout after change

---

### **Method 2: Emergency Reset** (If you forgot password)

#### **Option A: Using Reset Script** 🛠️

```bash
# Run the reset script
python reset_password.py
```

**Interactive Menu:**
```
Choose an option:
  1. Interactive reset (choose user)
  2. Reset admin to default (admin123)
  3. Quick reset (provide username & password)
```

**Example:**
```bash
# Option 1: Interactive
python reset_password.py
# Then follow prompts

# Option 3: Quick reset
python reset_password.py admin mynewpassword123
```

#### **Option B: Manual Database Reset** 🔧

```python
# Run in Python console or create a .py file
from werkzeug.security import generate_password_hash
import sqlite3

# Connect to database
conn = sqlite3.connect('database.db')
cur = conn.cursor()

# Reset password
username = 'admin'  # Change this
new_password = 'mynewpassword'  # Change this
hashed = generate_password_hash(new_password)

cur.execute("UPDATE users SET password = ? WHERE username = ?", 
           (hashed, username))
conn.commit()
conn.close()

print(f"✅ Password reset for {username}!")
```

#### **Option C: Reset Admin to Default**

```bash
python reset_password.py
# Choose option 2
# Admin password will be reset to: admin123
```

---

## 🔒 Password Requirements

### **Minimum Requirements:**
- ✅ At least 6 characters
- ✅ Cannot be same as current password
- ✅ Must match confirmation

### **Recommended:**
- ⭐ 10+ characters
- ⭐ Mix of uppercase and lowercase
- ⭐ Include numbers
- ⭐ Include special characters (!@#$%^&*)
- ⭐ Avoid common passwords
- ⭐ Don't use personal info

### **Examples:**

**❌ Weak Passwords:**
- `123456`
- `password`
- `admin`
- `qwerty`
- Your name or birthdate

**✅ Strong Passwords:**
- `MySecure@Pass2024`
- `L1c#Manager!2024`
- `BlueOcean$789Sky`
- `Coffee@Morning123`

---

## 🎨 Password Strength Indicator

When changing password, you'll see a color-coded strength meter:

| Strength | Color | Requirements |
|----------|-------|--------------|
| 🔴 Weak | Red | < 6 characters or very simple |
| 🟡 Medium | Yellow | 6-9 characters, some complexity |
| 🟢 Strong | Green | 10+ characters, good complexity |

---

## 🔐 Security Best Practices

### **Do's ✅**
1. **Change default password** immediately after first login
2. **Use unique passwords** for each account
3. **Update passwords** regularly (every 90 days)
4. **Use password manager** (LastPass, 1Password, Bitwarden)
5. **Enable 2FA** if available (coming soon)
6. **Never share** your password
7. **Logout** when done on shared computers

### **Don'ts ❌**
1. **Don't reuse** passwords across services
2. **Don't write** passwords on paper/sticky notes
3. **Don't share** passwords via email/chat
4. **Don't use** easily guessable passwords
5. **Don't save** passwords in plain text files
6. **Don't let browsers** save passwords on shared computers

---

## 🚨 What to Do If Password is Compromised

### **Immediate Actions:**

1. **Change password immediately**
   ```bash
   # Use web interface or reset script
   python reset_password.py
   ```

2. **Check activity logs**
   - Go to Dashboard
   - Review recent activity
   - Look for suspicious actions

3. **Notify admin** (if you're not admin)
   - Report the incident
   - Provide details of suspicious activity

4. **Change passwords** on other services
   - If you used same password elsewhere
   - Update to unique passwords

---

## 👥 Multiple Users Management

### **Creating New Users:**
1. Go to `/register`
2. Fill in username, email, password
3. Submit registration
4. Login with new credentials

### **For Admins: Resetting User Passwords**

```python
# Use reset script
python reset_password.py

# Choose option 1 (Interactive)
# Select the user from list
# Enter new temporary password
# Ask user to change it after login
```

---

## 📊 Password Change Workflow

```
User Login
    ↓
Click "🔑 Password"
    ↓
Enter Current Password
    ↓
Enter New Password ----→ Strength Check
    ↓                         ↓
Confirm Password         (Weak/Medium/Strong)
    ↓
Validate Match
    ↓
Hash New Password
    ↓
Update Database
    ↓
Log Activity
    ↓
Auto Logout
    ↓
Redirect to Login
    ↓
Login with New Password
```

---

## 🔍 Troubleshooting

### **Issue 1: "Current password is incorrect"**
**Solution:**
- Make sure you're entering the correct current password
- Check Caps Lock is off
- Try resetting via emergency method if forgotten

### **Issue 2: "Passwords do not match"**
**Solution:**
- New password and confirm password must be identical
- Check for typos
- Retype both fields carefully

### **Issue 3: "Password too short"**
**Solution:**
- Password must be at least 6 characters
- Use a longer, more secure password

### **Issue 4: "Cannot change password after reset"**
**Solution:**
- Clear browser cache
- Try different browser
- Check database connection
- Verify user exists in database

### **Issue 5: Forgot password and reset script doesn't work**
**Solution:**
```python
# Direct database access
import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect('database.db')
cur = conn.cursor()

# Check if user exists
cur.execute("SELECT username FROM users")
print("Available users:", cur.fetchall())

# Reset password
new_pass = generate_password_hash('temporarypass123')
cur.execute("UPDATE users SET password = ? WHERE username = 'admin'", (new_pass,))
conn.commit()
conn.close()

print("✅ Password reset to: temporarypass123")
```

---

## 📝 Activity Logging

All password-related actions are logged:

| Action | Description |
|--------|-------------|
| `PASSWORD_CHANGED` | Successful password change |
| `PASSWORD_CHANGE_FAILED` | Failed attempt (wrong current password) |
| `PASSWORD_RESET` | Admin reset user password |
| `LOGIN` | User logged in |
| `LOGIN_FAILED` | Failed login attempt |

**View logs:**
- Go to Dashboard
- Check "Recent Activity" section
- Monitor for suspicious activity

---

## 🎯 Quick Reference

### **Change Password via Web:**
```
1. Login
2. Click "🔑 Password" (top-right)
3. Fill form
4. Submit
5. Re-login
```

### **Emergency Reset:**
```bash
python reset_password.py
```

### **Reset Admin to Default:**
```bash
python reset_password.py
# Choose option 2
# Password becomes: admin123
```

### **Reset Specific User:**
```bash
python reset_password.py username newpassword
```

---

## ✅ Checklist

After changing password:

- [ ] Password is at least 6 characters
- [ ] Password is different from old one
- [ ] Password is unique (not used elsewhere)
- [ ] Password is written down securely (if needed)
- [ ] Can login with new password
- [ ] Activity is logged
- [ ] Other users notified (if admin)

---

## 🔮 Coming Soon

Future password features:
- [ ] 2-Factor Authentication (2FA)
- [ ] Email password reset
- [ ] Password expiry (force change every 90 days)
- [ ] Password history (prevent reuse of last 5 passwords)
- [ ] Forgot password flow
- [ ] Email notifications on password change
- [ ] Account lockout after failed attempts

---

## 📞 Need Help?

If you can't change your password:

1. Try the emergency reset script
2. Check database connection
3. Verify user exists
4. Contact system administrator
5. Check console for error messages

---

**🔐 Stay Secure! Change your default password now!**