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

    def add_file(self, username, filename, content):
        """
        Add a new file to the system.
        The file is owned by the uploader and its access is set to 'owned'.
        """
        file_id = str(uuid.uuid4())
        self.cursor.execute(
            "INSERT INTO files (file_id, owner, filename, content, access) VALUES (?, ?, ?, ?, ?)",
            (file_id, username, filename, content, "owned")
        )
        self.conn.commit()
        return file_id
    
    def get_user_aes(self, username):
        """Retrieve aes key for a given username"""
        self.cursor.execute('''SELECT key FROM users WHERE username = ?''', (username,))
        user_aes = self.cursor.fetchone()
        return user_aes
    
    def get_user_rsa(self, username):
        """Retrieve aes key for a given username"""
        self.cursor.execute('''SELECT pk FROM users WHERE username = ?''', (username,))
        user_rsa = self.cursor.fetchone()
        return user_rsa

    def edit_file(self, username, file_id, new_content):
        """
        Edit an existing file's content.
        Only allowed if the file is owned by the requesting user.
        """
        self.cursor.execute("SELECT owner FROM files WHERE file_id = ?", (file_id,))
        result = self.cursor.fetchone()
        if result and result[0] == username:
            self.cursor.execute(
                "UPDATE files SET content = ? WHERE file_id = ?",
                (new_content, file_id)
            )
            self.conn.commit()
        else:
            raise PermissionError("You do not have permission to edit this file.")

    def delete_file(self, username, file_id):
        """Delete a file if the user is the owner."""
        self.cursor.execute("SELECT owner FROM files WHERE file_id = ?", (file_id,))
        result = self.cursor.fetchone()
        if result and result[0] == username:
            self.cursor.execute("DELETE FROM files WHERE file_id = ?", (file_id,))
            self.cursor.execute("DELETE FROM shares WHERE file_id = ?", (file_id,))
            self.conn.commit()
        else:
            raise PermissionError("You do not have permission to delete this file.")

    def share_file(self, username, file_id, share_info):
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
          - filename: "shared" + original filename.
          - content: The provided shared content.
          - access: "shared".
        """
        # Retrieve the original file to get its filename and verify ownership.
        self.cursor.execute(
            "SELECT owner, filename FROM files WHERE file_id = ? AND access = 'owned'",
            (file_id,)
        )
        result = self.cursor.fetchone()
        if not result:
            raise ValueError("Original file not found or not owned by the user.")
        original_owner, original_filename = result
        if original_owner != username:
            raise PermissionError("You do not have permission to share this file.")

        # For each shared user, insert a new row.
        new_file_ids = {}
        for shared_user, shared_content in share_info.items():
            new_file_id = str(uuid.uuid4())
            shared_filename = "shared" + original_filename
            self.cursor.execute(
                "INSERT INTO files (file_id, owner, filename, content, access) VALUES (?, ?, ?, ?, ?)",
                (new_file_id, shared_user, shared_filename, shared_content, "shared")
            )
            new_file_ids[shared_user] = new_file_id
        self.conn.commit()
        return new_file_ids
    
    def view_file(self, username, file_id):
        """
        Retrieve the file's content and the AES key.
        - If the requester is the owner, the owner's AES key is retrieved.
        - If the requester is a shared user, the owner's AES key is retrieved.
        """
        # Query the file record.
        self.cursor.execute("SELECT owner, content FROM files WHERE file_id = ?", (file_id,))
        result = self.cursor.fetchone()
        if not result:
            raise ValueError("File not found")
        owner, content = result
        
        # Check access permission.
        if owner != username:
            self.cursor.execute(
                "SELECT 1 FROM shares WHERE file_id = ? AND shared_with = ?",
                (file_id, username)
            )
            if not self.cursor.fetchone():
                raise PermissionError("You do not have permission to access this file.")

        # Retrieve the AES key from the users table.
        # For both owner and shared users, the AES key of the file owner is returned.
        self.user_cursor.execute("SELECT key FROM users WHERE username = ?", (owner,))
        user_record = self.user_cursor.fetchone()
        if not user_record:
            raise ValueError("User record not found for owner")
        aes_key = user_record[0]
        return content, aes_key

    def get_users(self):
        """Return a list of all usernames from the users table."""
        self.user_cursor.execute("SELECT username FROM users")
        users = [row[0] for row in self.user_cursor.fetchall()]
        return users
 

    def get_files(self, username):
        """
        Return a list of files for the specified user.
        Each file is represented as a dictionary with keys: file_id, filename, and access.
        """
        self.cursor.execute(
            "SELECT file_id, filename, access FROM files WHERE owner = ?",
            (username,)
        )
        rows = self.cursor.fetchall()
        files = [{"file_id": fid, "filename": fname, "access": access} for fid, fname, access in rows]
        return files

    def close(self):
        """Close the database connection."""
        self.conn.close()


if __name__ == "__main__":
    fm = FileManager()

    # Owner uploads a file.
    owner = "alice"
    original_file_id = fm.add_file(owner, "document.txt", b"This is the original file content.")
    print("Original file ID:", original_file_id)

    # Owner shares the file with Bob and Carol.
    share_info = {
        "bob": b"Shared content for Bob.",
        "carol": b"Shared content for Carol."
    }
    shared_ids = fm.share_file(owner, original_file_id, share_info)
    print("Shared file IDs:", shared_ids)

    # View files for Bob.
    bob_files = fm.view_files("bob")
    print("Bob's files:", bob_files)

    # Bob retrieves his shared file.
    # Use the file id generated during share_file for Bob.
    bob_file_id = shared_ids.get("bob")
    if bob_file_id:
        content, access = fm.get_file("bob", bob_file_id)
        print("Bob's file content:", content.decode())  # Assuming text content
        print("File access type:", access)

    
    
