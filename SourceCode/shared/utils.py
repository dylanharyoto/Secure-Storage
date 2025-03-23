import sqlite3
import bcrypt
import re
import os

def init_database(database_file_name):
    # Initialize the database and create the users table if it does not exist
    conn = sqlite3.connect(database_file_name)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL, 
            key TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def hash_password(input_password):
    # Hash a password using bcrypt
    return bcrypt.hashpw(input_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def check_password(input_password, hashed_password):
    # Verify a password against a stored hash
    return bcrypt.checkpw(input_password.encode("utf-8"), hashed_password.encode("utf-8"))

def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def is_valid_password(password):
    return len(password) >= 8

def generate_aes():
    return os.urandom(16)

def split_aes(key):
    key_part_server = key[:8]  # First 64 bits
    key_part_client = key[8:]  # Last 64 bits
    return key_part_server, key_part_client
