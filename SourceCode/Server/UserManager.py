from sourcecode.Shared.Utils import Utils
from sourcecode.Client.CryptoManager import CryptoManager

class UserManager:
    @staticmethod
    def check_username(db_conn, username):
        """Check if a username exists in the users table."""
        cursor = db_conn.cursor()
        cursor.execute("SELECT * FROM Users WHERE username = ?", (username,))
        return cursor.fetchone() is not None
    @staticmethod
    def register_user(db_conn, username, password, encrypted_aes_key, public_key):
        """Register a new user with the provided details."""
        cursor = db_conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password, encrypted_aes_key, public_key) VALUES (?, ?, ?, ?)",
            (username, password, encrypted_aes_key, public_key)
        )
        db_conn.commit()
    @staticmethod
    def get_password(db_conn, username):
        """Authenticate a user by checking their password."""
        cursor = db_conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        stored_hash = result[0]
        return stored_hash
    @staticmethod
    def reset_password(db_conn, username, new_password, new_aes):
        """Reset a user's password and AES key."""
        cursor = db_conn.cursor()
        cursor.execute(
            "UPDATE users SET password = ?, encrypted_aes_key = ? WHERE username = ?",
            (new_password, new_aes, username)
        )
        db_conn.commit()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone() is not None
        return result