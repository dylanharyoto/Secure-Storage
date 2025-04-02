import sqlite3
import bcrypt
import re
import os

def init_database(db_file_name, table_name):
    """Initialize the database and create the specified table if it does not exist."""
    conn = sqlite3.connect(db_file_name)
    cursor = conn.cursor()
    try:
        cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS {table_name} (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL, 
                key TEXT NOT NULL,
                pk TEXT NOT NULL
            )
        ''')
        conn.commit()
    finally:
        conn.close()

def hash_password(input_password):
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(input_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def check_password(input_password, hashed_password):
    """Verify a password against a stored hash using bcrypt."""
    return bcrypt.checkpw(input_password.encode("utf-8"), hashed_password.encode("utf-8"))

def check_username_regex(username):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, username) is not None

def check_password_regex(password):
    return len(password) >= 8