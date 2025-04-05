from SourceCode.Shared.Utils import Utils

class UserManager:
    @staticmethod
    def check_username(db_conn, username):
        """Check if a username exists in the users table."""
        cursor = db_conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        exists = cursor.fetchone() is not None
        return exists

    @staticmethod
    def register_user(db_conn, username, password, encrypted_aes_key, public_key):
        """Register a new user with the provided details."""
        cursor = db_conn.cursor()
        hashed_password = Utils.hash_password(password)
        cursor.execute(
            "INSERT INTO users (username, password, encrypted_aes_key, public_key) VALUES (?, ?, ?, ?)",
            (username, hashed_password, encrypted_aes_key, public_key)
        )
        db_conn.commit()
        return True
    
    @staticmethod
    def login_user(db_conn, username, password):
        """Authenticate a user by checking their password."""
        cursor = db_conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if not result:
            return False  # Username not found
        stored_hash = result[0]
        return Utils.check_password(password, stored_hash)
    
    @staticmethod
    def reset_password(db_conn, username, new_password, new_aes):
        """Reset a user's password and AES key."""
        cursor = db_conn.cursor()
        new_hashed_password = Utils.hash_password(new_password)
        cursor.execute(
            "UPDATE users SET password = ?, encrypted_aes_key = ? WHERE username = ?",
            (new_hashed_password, new_aes, username)
        )
        db_conn.commit()
        return True