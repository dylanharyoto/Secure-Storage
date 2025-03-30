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

    def _create_files_tables(self):
        """Creates the tables for file metadata and sharing."""
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS files (
                file_id TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                filename TEXT NOT NULL,
                content BLOB NOT NULL
            )
        """)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS shares (
                file_id TEXT NOT NULL,
                shared_with TEXT NOT NULL,
                FOREIGN KEY(file_id) REFERENCES files(file_id)
            )
        """)
        self.conn.commit()

    def add_file(self, username, filename, content):
        """Add a new file to the files database."""
        file_id = str(uuid.uuid4())
        self.cursor.execute(
            "INSERT INTO files (file_id, owner, filename, content) VALUES (?, ?, ?, ?)",
            (file_id, username, filename, content)
        )
        self.conn.commit()
        return file_id

    def edit_file(self, username, file_id, new_content):
        """Edit an existing file if the user is the owner."""
        self.cursor.execute("SELECT owner FROM files WHERE file_id = ?", (file_id,))
        result = self.cursor.fetchone()
        if result and result[0] == username:
            self.cursor.execute("UPDATE files SET content = ? WHERE file_id = ?", (new_content, file_id))
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

    def share_file(self, username, file_id, users):
        """
        Share a file with designated users.
        The file owner must be the one sharing the file.
        """
        self.cursor.execute("SELECT owner FROM files WHERE file_id = ?", (file_id,))
        result = self.cursor.fetchone()
        if result and result[0] == username:
            for user in users:
                self.cursor.execute("INSERT INTO shares (file_id, shared_with) VALUES (?, ?)", (file_id, user))
            self.conn.commit()
        else:
            raise PermissionError("You do not have permission to share this file.")

    def get_file(self, username, file_id):
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

    def get_user(self):
        """Return a list of all usernames from the users table."""
        self.user_cursor.execute("SELECT username FROM users")
        users = [row[0] for row in self.user_cursor.fetchall()]
        return users

    def view_files(self, username):
        """
        Retrieve all file names and IDs that are either owned by the user or shared with the user.
        Returns a dictionary in the format: {file_id: filename}
        """
        self.cursor.execute("""
            SELECT file_id, filename FROM files 
            WHERE owner = ? OR file_id IN (
                SELECT file_id FROM shares WHERE shared_with = ?
            )
        """, (username, username))
        files = {file_id: filename for file_id, filename in self.cursor.fetchall()}
        return files

if __name__ == "__main__":
    # Initialize FileManager (files are stored in files.db; users.db path is resolved relative to this file)
    fm = FileManager()

    # Display all registered users.
    print("Registered users:", fm.get_user())

    # Simulate Alice uploading a file 
    try:
        file_id = fm.add_file("alice", "secret.txt", b"This is Alice's secret file content.")
        print("Alice uploaded a file. File ID:", file_id)
    except Exception as e:
        print("Error uploading file for Alice:", e)

    # Alice shares the file with Bob
    try:
        fm.share_file("alice", file_id, ["bob"])
        print("Alice shared the file with Bob.")
    except Exception as e:
        print("Error sharing file:", e)

    # Bob views his accessible files (both his and shared with him) 
    try:
        bob_files = fm.view_files("bob")
        print("Files accessible by Bob:", bob_files)
    except Exception as e:
        print("Error retrieving Bob's files:", e)

    # Bob retrieves the shared file content along with the AES key 
    try:
        content, aes_key = fm.get_file("bob", file_id)
        print("Bob retrieved file content:", content.decode())
        print("AES key for the file (from owner's record):", aes_key)
    except Exception as e:
        # This might happen if Amy is not a real user. Please replace the usernames with registered user names and retry.
        print("Error retrieving file for Bob:", e)
