class PendingManager:
    @staticmethod
    def store_pending(db_conn, username, password, encrypted_aes_key, public_key):
        """Store registration data in pending_registrations table."""
        cursor = db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO pendings (username, password, encrypted_aes_key, public_key)
            VALUES (?, ?, ?, ?)
        ''', (username, password, encrypted_aes_key, public_key))
        db_conn.commit()
    @staticmethod
    def get_pending(db_conn, username):
        """Retrieve pending registration data for a user."""
        cursor = db_conn.cursor()
        cursor.execute('''
            SELECT password, encrypted_aes_key, public_key FROM pendings
            WHERE username = ?
        ''', (username,))
        return cursor.fetchone()
    @staticmethod
    def delete_pending(db_conn, username):
        """Delete a pending registration after successful confirmation."""
        cursor = db_conn.cursor()
        cursor.execute('DELETE FROM pendings WHERE username = ?', (username,))
        db_conn.commit()
