from sqlite3 import connect

conn = connect("erp.db")
cur = conn.cursor()

cur.execute('''CREATE TABLE IF NOT EXISTS users (
id INTEGER PRIMARY KEY AUTOINCREMENT,
name TEXT NOT NULL,
email TEXT UNIQUE NOT NULL,
password TEXT NOT NULL,
photo_filename TEXT
)''')

cur.execute('''CREATE TABLE IF NOT EXISTS admins (
id INTEGER PRIMARY KEY AUTOINCREMENT,
username TEXT UNIQUE NOT NULL,
password TEXT NOT NULL
)''')

cur.execute('''CREATE TABLE IF NOT EXISTS attendance (
id INTEGER PRIMARY KEY AUTOINCREMENT,
user_id INTEGER NOT NULL,
date TEXT NOT NULL,
status TEXT NOT NULL,
FOREIGN KEY(user_id) REFERENCES users(id)
)''')

cur.execute('''CREATE TABLE IF NOT EXISTS results (
id INTEGER PRIMARY KEY AUTOINCREMENT,
user_id INTEGER NOT NULL,
subject TEXT NOT NULL,
marks TEXT NOT NULL,
FOREIGN KEY(user_id) REFERENCES users(id)
)''')