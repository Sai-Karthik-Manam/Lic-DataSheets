# Run this in Python console
from werkzeug.security import generate_password_hash
import sqlite3

# Connect to database
conn = sqlite3.connect('database.db')
cur = conn.cursor()

# Reset admin password
new_password = 'newpassword123'  # Change this
hashed = generate_password_hash(new_password)
cur.execute("UPDATE users SET password = ? WHERE username = 'admin'", (hashed,))
conn.commit()
conn.close()

print(f"✅ Password reset! New password: {new_password}")