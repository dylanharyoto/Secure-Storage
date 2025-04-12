import time

class LogManager:
    @staticmethod
    def log_action(db_conn, username, action, details=None, status="success"):
        """Log an action to the audit_logs table."""
        timestamp = int(time.time())
        cursor = db_conn.cursor()
        cursor.execute('''
            INSERT INTO logs (timestamp, username, action, details, status)
            VALUES (?, ?, ?, ?, ?)
        ''', (timestamp, username, action, details, status))
        db_conn.commit()
    
    def get_logs(db_conn):
        cursor = db_conn.cursor()
        cursor.execute("SELECT timestamp, username, action, details, status FROM logs ORDER BY timestamp DESC")
        return cursor.fetchall()