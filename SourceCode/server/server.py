import sqlite3
from SourceCode.shared.utils import generate_aes, hash_password, split_aes

# Constants
DB_FILENAME="users.db"

class Server:
    def __init__(self):
        self.conn = None
        self.cursor = None
        
    def open_conn(self):
        self.conn = sqlite3.connect(DB_FILENAME)
        self.cursor = self.conn.cursor()

    def close_conn(self):
        self.conn.close()

    def check_username_exists(self, username):
        self.cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        if self.cursor.fetchone():
            return True
        return False

    def register_user(self, username, password):
        client_aes, server_aes = split_aes(generate_aes())
        self.cursor.execute("INSERT INTO users (username, password, key) VALUES (?, ?, ?)", (username, hash_password(password), server_aes))
        self.conn.commit()
        return client_aes

    def login_user(self, username, password):
        self.cursor.execute("SELECT password FROM users WHERE username = ?", (username, ))
        return self.cursor.fetchone() == hash_password(password)

    def reset_password(self, username, password):
        self.cursor.execute("UPDATE users SET password = ? WHERE username = ?", (hash_password(password), username))
        self.conn.commit()
