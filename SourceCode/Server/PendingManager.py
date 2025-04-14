class PendingManager:
    @staticmethod
    def store_pending(db_conn, username, password, encrypted_aes_key, public_key):
        """
        Store or update a pending user record in the 'pendings' table.

        Parameters:
        - db_conn: SQLite3 database connection object
        - username (str): Username of the pending user
        - password (str): Hashed password
        - encrypted_aes_key (bytes): AES key encrypted with a recovery or public key
        - public_key (bytes): User's RSA public key
        """
        cursor = db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO pendings (username, password, encrypted_aes_key, public_key)
            VALUES (?, ?, ?, ?)
        ''', (username, password, encrypted_aes_key, public_key))
        db_conn.commit()
    @staticmethod
    def get_pending(db_conn, username):
        """
        Retrieve a pending user's record from the 'pendings' table.

        Parameters:
        - db_conn: SQLite3 database connection object
        - username (str): Username to query

        Returns:
        - tuple: (password, encrypted_aes_key, public_key) if found
        - None: if the username does not exist
        """
        cursor = db_conn.cursor()
        cursor.execute('''
            SELECT password, encrypted_aes_key, public_key FROM pendings
            WHERE username = ?
        ''', (username,))
        return cursor.fetchone()
    @staticmethod
    def delete_pending(db_conn, username):
        """
        Delete a pending user's record from the 'pendings' table.

        Parameters:
        - db_conn: SQLite3 database connection object
        - username (str): Username to delete
        """
        cursor = db_conn.cursor()
        cursor.execute('DELETE FROM pendings WHERE username = ?', (username,))
        db_conn.commit()
