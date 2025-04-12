class PendingManager:
    @staticmethod
    def store_pending(db_conn, username, password, encrypted_aes_key, public_key):
        cursor = db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO pendings (username, password, encrypted_aes_key, public_key)
            VALUES (?, ?, ?, ?)
        ''', (username, password, encrypted_aes_key, public_key))
        db_conn.commit()
    @staticmethod
    def get_pending(db_conn, username):
        cursor = db_conn.cursor()
        cursor.execute('''
            SELECT password, encrypted_aes_key, public_key FROM pendings
            WHERE username = ?
        ''', (username,))
        return cursor.fetchone()
    @staticmethod
    def delete_pending(db_conn, username):
        cursor = db_conn.cursor()
        cursor.execute('DELETE FROM pendings WHERE username = ?', (username,))
        db_conn.commit()
