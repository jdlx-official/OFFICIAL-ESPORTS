import sqlite3

conn = sqlite3.connect("users.db")
cur = conn.cursor()

try:
    cur.execute("ALTER TABLE tournament ADD COLUMN notified BOOLEAN DEFAULT 0;")
    print("✔ Column added successfully!")
except Exception as e:
    print("⚠ Error:", e)

conn.commit()
conn.close()
