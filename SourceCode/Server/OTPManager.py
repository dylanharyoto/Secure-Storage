import random
import time
class OTPManager:
    @staticmethod
    def generate_otp():
        """Generate a 6-digit OTP."""
        return str(random.randint(100000, 999999))

    @staticmethod
    def store_otp(db_conn, username, otp_type, otp):
        """Store OTP in the database with a timestamp."""
        timestamp = int(time.time())
        cursor = db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO otps (username, otp_type, otp, timestamp)
            VALUES (?, ?, ?, ?)
        ''', (username, otp_type, otp, timestamp))
        db_conn.commit()

    @staticmethod
    def verify_otp(db_conn, username, otp_type, otp):
        """Verify the OTP and invalidate it if correct."""
        cursor = db_conn.cursor()
        cursor.execute('''
            SELECT otp, timestamp FROM otps
            WHERE username = ? AND otp_type = ?
        ''', (username, otp_type))
        result = cursor.fetchone()
        if result:
            stored_otp, timestamp = result
            current_time = int(time.time())
            if current_time - timestamp > 600:  # 10-minute expiration
                return False, "OTP expired"
            if stored_otp == otp:
                cursor.execute('''
                    DELETE FROM otps WHERE username = ? AND otp_type = ?
                ''', (username, otp_type))
                db_conn.commit()
                return True, "OTP verified"
            return False, "Invalid OTP"
        return False, "No OTP found"

    @staticmethod
    def store_pending_registration(db_conn, username, password, encrypted_aes_key, public_key):
        """Store registration data in pending_registrations table."""
        cursor = db_conn.cursor()
        cursor.execute('''
            INSERT INTO pendings (username, password, encrypted_aes_key, public_key)
            VALUES (?, ?, ?, ?)
        ''', (username, password, encrypted_aes_key, public_key))
        db_conn.commit()

    @staticmethod
    def get_pending_registration(db_conn, username):
        """Retrieve pending registration data for a user."""
        cursor = db_conn.cursor()
        cursor.execute('''
            SELECT password, encrypted_aes_key, public_key FROM pendings
            WHERE username = ?
        ''', (username,))
        return cursor.fetchone()

    @staticmethod
    def delete_pending_registration(db_conn, username):
        """Delete a pending registration after successful confirmation."""
        cursor = db_conn.cursor()
        cursor.execute('DELETE FROM pendings WHERE username = ?', (username,))
        db_conn.commit()
