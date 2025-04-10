import sqlite3
# import bcrypt
import re
class Utils:
    @staticmethod
    def init_db(db_file_name, table_name, schema):
        """Initialize the database and create the specified table if it does not exist."""
        conn = sqlite3.connect(db_file_name)
        cursor = conn.cursor()
        columns = [f"{col_name} {col_type}" for col_name, col_type in schema.items()]
        try:
            cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS {table_name} (
                    {', '.join(columns)}
                )
            ''')
            conn.commit()
            print(f"[STATUS] Table '{table_name}' initialized successfully in '{db_file_name}'.")
        except sqlite3.Error as error:
            print(f"[ERROR] Database error: {error}")
        finally:
            conn.close()
   
    @staticmethod
    def check_username_regex(username):
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, username) is not None
    @staticmethod
    def check_password_regex(password):
        return len(password) >= 8
    @staticmethod
    def check_file_id_regex(file_id):
        pattern = r'^[0-9(a-f|A-F)]{8}-[0-9(a-f|A-F)]{4}-4[0-9(a-f|A-F)]{3}-[89ab][0-9(a-f|A-F)]{3}-[0-9(a-f|A-F)]{12}$'
        return re.match(pattern, file_id)