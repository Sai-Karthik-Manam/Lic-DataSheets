import sqlite3

conn = sqlite3.connect('database.db')
cur = conn.cursor()

# See all clients
cur.execute("SELECT id, name FROM clients")
print("Clients:", cur.fetchall())

# See all documents
cur.execute("SELECT client_id, document_type, file_name FROM documents")
print("Documents:", cur.fetchall())

conn.close()