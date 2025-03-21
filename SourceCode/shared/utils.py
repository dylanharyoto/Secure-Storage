import sqlite3
import bcrypt

def init_database(database_file_name):
    # Initialize the database and create the users table if it does not exist
    conn = sqlite3.connect(database_file_name)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
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
