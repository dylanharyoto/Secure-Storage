import sqlite3
import os
from SourceCode.shared.utils import generate_aes, hash_password, split_aes

# Constants
DB_FILENAME="users.db"

class Server:
    def __init__(self, db_filename="users.db"):
        self.db_filename = os.path.join(os.path.dirname(__file__), db_filename)
        self.conn = None
        self.cursor = None

    def open_conn(self):
        if self.conn is not None:
            self.conn = sqlite3.connect(self.db_filename)
            self.cursor = self.conn.cursor()

    def close_conn(self):
        if self.conn is not None:
            self.conn.close()
            self.conn = None
            self.cursor = None

    def check_username_exists(self, username):
        self.open_conn()
        try:
            self.cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            return self.cursor.fetchone() is not None
        finally:
            self.close_conn()
        
    def register_user(self, username, password):
        self.open_conn()
        try:
            client_aes, server_aes = split_aes(generate_aes())
            self.cursor.execute(
                "INSERT INTO users (username, password, key) VALUES (?, ?, ?)", 
                (username, hash_password(password), server_aes)
            )
            self.conn.commit()
            return client_aes
        finally:
            self.close_conn()

    def login_user(self, username, password):
        self.open_conn()
        try:
            self.cursor.execute("SELECT password FROM users WHERE username = ?", (username, ))
            result = self.cursor.fetchone()
            if result is None:
                return False
            return result[0] == hash_password(password)
        finally:
            self.close_conn()

    def reset_password(self, username, password):
        self.open_conn()
        try:
            self.cursor.execute(
                "UPDATE users SET password = ? WHERE username = ?",
                (hash_password(password), username)
            )
            self.conn.commit()
        finally:
            self.close_conn()
