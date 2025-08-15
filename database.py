import sqlite3
from datetime import datetime

DB_FILE = "users.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            username TEXT,
            first_name TEXT,
            join_date TEXT DEFAULT 0,
            scan_count INTEGER DEFAULT 0
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS user_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            scan_type TEXT,
            result TEXT,
            date TEXT,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )
    """)
    conn.commit()
    conn.close()

def add_user(user_id, username, first_name):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT 1 FROM users WHERE user_id = ?", (user_id,))
    if c.fetchone() is None:
        c.execute(
            "INSERT INTO users (user_id, username, first_name, join_date) VALUES (?, ?, ?, ?)",
            (user_id, username, first_name, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()
    conn.close()

def log_scan(user_id, scan_type, result):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE users SET scan_count = scan_count + 1 WHERE user_id=?", (user_id,))
    c.execute("INSERT INTO user_scans (user_id, scan_type, result, date) VALUES (?, ?, ?, ?)",
              (user_id, scan_type, result, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    c.execute("""
        DELETE FROM user_scans WHERE id NOT IN (
            SELECT id FROM user_scans WHERE user_id=? ORDER BY id DESC LIMIT 3
        ) AND user_id=?
    """, (user_id, user_id))
    conn.commit()
    conn.close()

def get_last_scans(user_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT scan_type, result, date FROM user_scans WHERE user_id=? ORDER BY id DESC LIMIT 3", (user_id,))
    scans = c.fetchall()
    conn.close()
    return scans

def get_user_info(user_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT username, first_name, join_date, scan_count FROM users WHERE user_id=?", (user_id,))
    data = c.fetchone()
    conn.close()
    return data
