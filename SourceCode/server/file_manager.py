import sqlite3
import re
import bcrypt

import os


class FileManager:
    def __init__(self, base_directory="user_files", db_path="file_metadata.db"):
        # Ensure the base directory for file storage exists.
        self.base_directory = base_directory
        os.makedirs(self.base_directory, exist_ok=True)

        # Connect to the SQLite database (creates if it doesn't exist)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self._create_tables()

    def _create_tables(self):
        # Create table for file metadata.
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                file_id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner TEXT NOT NULL,
                filename TEXT NOT NULL,
                filepath TEXT NOT NULL
            )
        ''')
        # Create table for file sharing information.
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS shared_files (
                file_id INTEGER,
                shared_user TEXT,
                PRIMARY KEY (file_id, shared_user),
                FOREIGN KEY (file_id) REFERENCES files (file_id)
            )
        ''')
        self.conn.commit()

    def _sanitize_filename(self, filename):
        """
        Sanitize the file name to prevent path traversal attacks.
        This removes any directory components.
        """
        return os.path.basename(filename)

    def add_file(self, username, filename, content):
        """
        Allows a user to add/upload a file.
        The file is stored under a subdirectory named after the user.
        """
        safe_filename = self._sanitize_filename(filename)

        # Create a dedicated directory for the user if it doesn't exist.
        user_dir = os.path.join(self.base_directory, username)
        os.makedirs(user_dir, exist_ok=True)

        # Insert metadata first. The file_id is auto-generated.
        self.cursor.execute('''
            INSERT INTO files (owner, filename, filepath) 
            VALUES (?, ?, ?)
        ''', (username, safe_filename, ""))
        file_id = self.cursor.lastrowid

        # Create a unique file name using file_id.
        file_path = os.path.join(user_dir, f"{file_id}_{safe_filename}")

        # Save the file content.
        with open(file_path, "wb") as f:
            f.write(content)

        # Update the file record with the correct file_path.
        self.cursor.execute('''
            UPDATE files SET filepath = ? WHERE file_id = ?
        ''', (file_path, file_id))
        self.conn.commit()

        return file_id

    def edit_file(self, username, file_id, new_content):
        """
        Allows a user to edit an existing file.
        Only the file owner is permitted to update its content.
        """
        self.cursor.execute('''
            SELECT owner, filepath FROM files WHERE file_id = ?
        ''', (file_id,))
        result = self.cursor.fetchone()
        if not result:
            raise ValueError("File not found")
        owner, file_path = result
        if owner != username:
            raise PermissionError("You do not have permission to edit this file")

        # Overwrite the file content.
        with open(file_path, "wb") as f:
            f.write(new_content)
        return True

    def delete_file(self, username, file_id):
        """
        Allows a user to delete a file.
        Only the file owner is allowed to delete it.
        """
        self.cursor.execute('''
            SELECT owner, filepath FROM files WHERE file_id = ?
        ''', (file_id,))
        result = self.cursor.fetchone()
        if not result:
            raise ValueError("File not found")
        owner, file_path = result
        if owner != username:
            raise PermissionError("You do not have permission to delete this file")

        # Delete the file from disk.
        if os.path.exists(file_path):
            os.remove(file_path)

        # Delete the file metadata and sharing records.
        self.cursor.execute('''
            DELETE FROM files WHERE file_id = ?
        ''', (file_id,))
        self.cursor.execute('''
            DELETE FROM shared_files WHERE file_id = ?
        ''', (file_id,))
        self.conn.commit()
        return True

    def share_file(self, username, file_id, designated_users):
        """
        Allows the owner of a file to share it with designated users.
        The designated users will be able to read the file via their client.
        """
        # Verify that the file exists and that the requester is the owner.
        self.cursor.execute('''
            SELECT owner FROM files WHERE file_id = ?
        ''', (file_id,))
        result = self.cursor.fetchone()
        if not result:
            raise ValueError("File not found")
        owner = result[0]
        if owner != username:
            raise PermissionError("You do not have permission to share this file")

        # Insert each designated user into the shared_files table.
        for user in designated_users:
            try:
                self.cursor.execute('''
                    INSERT INTO shared_files (file_id, shared_user)
                    VALUES (?, ?)
                ''', (file_id, user))
            except sqlite3.IntegrityError:
                # This means the sharing record already exists, so we can skip it.
                continue
        self.conn.commit()
        return True

    def get_file(self, username, file_id):
        """
        Returns the content of a file if the requesting user is either the owner
        or has been granted access via sharing.
        """
        self.cursor.execute('''
            SELECT owner, filepath FROM files WHERE file_id = ?
        ''', (file_id,))
        result = self.cursor.fetchone()
        if not result:
            raise ValueError("File not found")
        owner, file_path = result

        # Check if the user is the owner.
        if owner == username:
            pass
        else:
            # Check if the user is in the shared_files table.
            self.cursor.execute('''
                SELECT 1 FROM shared_files WHERE file_id = ? AND shared_user = ?
            ''', (file_id, username))
            if not self.cursor.fetchone():
                raise PermissionError("You do not have permission to access this file")

        # Read and return the file content.
        with open(file_path, "rb") as f:
            content = f.read()
        return content

    def close(self):
        """Close the database connection."""
        self.conn.close()


# Example usage:
if __name__ == "__main__":
    fm = FileManager()

    # User 'alice' uploads a file.
    file_id = fm.add_file("alice", "report.txt", b"This is Alice's confidential report.")
    print("Alice uploaded file with ID:", file_id)

    # Alice edits her file.
    fm.edit_file("alice", file_id, b"Updated content for Alice's report.")

    # Alice shares the file with 'bob'.
    fm.share_file("alice", file_id, ["bob"])
    
    # Bob attempts to access the shared file.
    try:
        content = fm.get_file("bob", file_id)
        print("Bob accessed file content:", content.decode())
    except PermissionError as e:
        print("Access denied for Bob:", e)

    # Unauthorized user 'eve' tries to access the file.
    try:
        content = fm.get_file("eve", file_id)
        print("Eve accessed file content:", content.decode())
    except PermissionError as e:
        print("Access denied for Eve:", e)

    # Close the file manager when done.
    fm.close()


    
