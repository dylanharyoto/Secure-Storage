import sqlite3
from SourceCode.shared.utils import generate_aes, hash_password, split_aes

# Global Variables
conn, cursor = None, None

# Constants
DB_FILENAME="users.db"

def open_conn():
    conn = sqlite3.connect(DB_FILENAME)
    cursor = conn.cursor()

def close_conn():
    conn.close()

def check_username_exists(username):
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        return True
    return False

def register_user(username, password):
    client_aes, server_aes = split_aes(generate_aes())
    cursor.execute("INSERT INTO users (username, password, key) VALUES (?, ?, ?)", (username, hash_password(password), server_aes))
    conn.commit()
    return client_aes

def login_user(username, password):
    cursor.execute("SELECT password FROM users WHERE username = ?", (username, ))
    return cursor.fetchone() == hash_password(password)

def reset_password(username, password):
    cursor.execute("UPDATE users SET password = ? WHERE username = ?", (hash_password(password), username))
    conn.commit()
