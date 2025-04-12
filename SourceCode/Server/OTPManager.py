import random
import time
import smtplib
from email.mime.text import MIMEText
from enum import Enum

class OTPMessage(Enum):
   EXPIRED = "OTP expired"
   VERIFIED = "OTP verified"
   INVALID = "OTP invalid"
   NOT_FOUND = "OTP not found"

class OTPManager:
    @staticmethod
    def generate_otp():
        return str(random.randint(100000, 999999))
    @staticmethod
    def send_otp(to_email, otp):
        from_email = "dylanharyoto.polyu@gmail.com" 
        from_password = "wyszwoimgqcycevd" # dont change
        subject = "Your OTP Code"
        message = f"Your OTP code is {otp}. It is valid for 10 minutes."
        msg = MIMEText(message)
        msg['Subject'] = subject
        msg['From'] = from_email
        msg['To'] = to_email
        try:
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(from_email, from_password)
            server.sendmail(from_email, to_email, msg.as_string())
            server.quit()
            print(f"[STATUS] OTP sent to {to_email}")
        except Exception as e:
            print(f"[ERROR] Failed to send email: {e}")
            raise
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
                return False, OTPMessage.EXPIRED
            if stored_otp == otp:
                cursor.execute('''
                    DELETE FROM otps WHERE username = ? AND otp_type = ?
                ''', (username, otp_type))
                db_conn.commit()
                return True, OTPMessage.VERIFIED
            return False, OTPMessage.INVALID
        return False, OTPMessage.NOT_FOUND
    