import sqlite3
import os
import uuid

class FileManager:
    def __init__(self, files_db="files.db", users_db=None):
        # Initialize the files database connection.
        self.conn = sqlite3.connect(files_db, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self._create_files_tables()
        
        # Initialize the users database connection.
        # If no users_db path is provided, use the default path.
        if users_db is None:
            users_db = os.path.join(os.path.dirname(__file__), "data", "users.db")
        self.user_conn = sqlite3.connect(users_db, check_same_thread=False)
        self.user_cursor = self.user_conn.cursor()

    @staticmethod
    def check_file_id(db_conn, username, file_id):
        """
        Check if a file is owned (either "shared" or "owned" access) a user
        """
        cursor = db_conn.cursor()
        cursor.execute(
            "SELECT file_id FROM files WHERE file_id = ? AND owner = ?",
            (file_id, username)
        )
        result = cursor.fetchone()
        return result is not None

    @staticmethod
    def upload_file(db_conn, username, file_name, content):
        """
        Add a new file to the system.
        The file is owned by the uploader and its access is set to 'owned'.
        """
        file_id = str(uuid.uuid4())
        cursor = db_conn.cursor()
        cursor.execute(
            "INSERT INTO files (file_id, owner, file_name, content, access) VALUES (?, ?, ?, ?, ?)",
            (file_id, username, file_name, content, "owned")
        )
        db_conn.commit()
        return file_id
    
    @staticmethod
    def edit_file(db_conn, username, file_name, file_id, new_content):
        """
        Edit an existing file's content.
        Only allowed if the file is owned by the requesting user.
        """
        cursor = db_conn.cursor()
        cursor.execute("SELECT owner FROM files WHERE file_id = ?", (file_id,))
        result = cursor.fetchone()
        if result and result[0] == username:
            cursor.execute(
                "UPDATE files SET content = ?, file_name = ? WHERE file_id = ?",
                (new_content, file_name, file_id)
            )
            db_conn.commit()
        else:
            raise PermissionError("You do not have permission to edit this file.")
        
    @staticmethod
    def delete_file(db_conn, username, file_id):
        """Delete a file if the user is the owner."""
        cursor = db_conn.cursor()
        cursor.execute("SELECT owner FROM files WHERE file_id = ?", (file_id,))
        result = cursor.fetchone()
        if result and result[0] == username:
            cursor.execute("DELETE FROM files WHERE file_id = ?", (file_id,))
            db_conn.commit()
        else:
            raise PermissionError("You do not have permission to delete this file.")
    @staticmethod
    def share_file(db_conn, username, file_id, shared_user, shared_data):
        """
        Share a file with designated users.
        
        Parameters:
          username   : The owner who is sharing the file.
          file_id    : The original file_id (must belong to username).
          share_info : A dict mapping each shared user to their shared file content.
                       Example: { "bob": b"Bob's version of file content", ... }
        
        For each entry in share_info, a new row is created in the files table:
          - file_id: New generated ID.
          - owner: The shared user. 
          - file_name: "shared" + original file_name.
          - content: The provided shared content.
          - access: "shared".
        """
        # Retrieve the original file to get its file_name and verify ownership.
        cursor = db_conn.cursor()
        cursor.execute(
            "SELECT owner, file_name FROM files WHERE file_id = ? AND access = 'owned'",
            (file_id,)
        )
        result = cursor.fetchone()
        if not result:
            raise ValueError("Original file not found or not owned by the user.")
        original_owner, original_file_name = result
        if original_owner != username:
            raise PermissionError("You do not have permission to share this file.")

        # For each shared user, insert a new row.

        new_file_id = str(uuid.uuid4())
        shared_file_name = "shared" + original_file_name
        cursor.execute(
            "INSERT INTO files (file_id, owner, file_name, content, access) VALUES (?, ?, ?, ?, ?)",
            (new_file_id, shared_user, shared_file_name, shared_data, "shared")
        )
        db_conn.commit()
        return new_file_id
    @staticmethod
    def get_files(db_conn, username):
        """
        Return a list of files for the specified user.
        Each file is represented as a dictionary with keys: file_id, file_name, and access.
        """
        cursor = db_conn.cursor()
        cursor.execute(
            "SELECT file_id, file_name, access FROM files WHERE owner = ?",
            (username,)
        )
        rows = cursor.fetchall()
        files = [{"file_id": fid, "file_name": fname, "access": access} for fid, fname, access in rows]
        return files
    @staticmethod
    def view_file(db_conn, username, file_id):
        """
        Retrieve a file's content.
        Checks that the file's owner matches the username.
        Returns a tuple (content, access) if access is permitted.
        """
        cursor = db_conn.cursor()
        cursor.execute(
            "SELECT owner, content, access, file_name FROM files WHERE file_id = ?",
            (file_id,)
        )
        result = cursor.fetchone()
        if not result:
            raise ValueError("File not found.")
        owner, content, access, file_name = result
        if owner != username:
            raise PermissionError("You do not have permission to access this file.")
        return content, access, file_name
    @staticmethod
    def get_users(db_conn):
        """Return a list of all usernames from the users table."""
        cursor = db_conn.cursor()
        cursor.execute("SELECT username FROM users")
        users = [row[0] for row in cursor.fetchall()]
        return users
    
    @staticmethod
    def get_aes_key(db_conn, username):
        """Retrieve aes key for a given username"""
        cursor = db_conn.cursor()
        cursor.execute('''SELECT encrypted_aes_key FROM users WHERE username = ?''', (username,))
        user_aes = cursor.fetchone()
        return user_aes
    
    @staticmethod
    def get_rsa_key(db_conn, username):
        """Retrieve publis RSA key for a given username"""
        cursor = db_conn.cursor()
        cursor.execute('''SELECT public_key FROM users WHERE username = ?''', (username,))
        user_rsa = cursor.fetchone()
        return user_rsa

