import sqlite3
import re
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
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
            if table_name == "otps":
                cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_otps_unique ON otps (username, otp_type)")
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
    
    @staticmethod
    def send_registration_email(to_email, secret_key_content, recovery_key_content):
        """
        Send the RSA secret key and recovery key to a user's email as attachments.

        Parameters:
        - to_email (str): The recipient's email address
        - secret_key_content (str): The RSA secret key text
        - recovery_key_content (str): The recovery key text
        """
        from_email = "dylanharyoto.polyu@gmail.com"
        from_password = "wyszwoimgqcycevd"
        subject = "Your Recovery Key and Secret Key from RSA"
        body = (
            "Dear User,\n\n"
            "Attached are your confidential keys:\n"
            "secret_key.txt: Your RSA Secret Key\n"
            "recovery_key.txt: Your Recovery Key\n\n"
            "Please store them safely and do not share them with anyone.\n\n"
            "Best regards,\nCOMP3334 Group 10"
        )

        msg = MIMEMultipart()
        msg['Subject'] = subject
        msg['From'] = from_email
        msg['To'] = to_email
        msg.attach(MIMEText(body, 'plain'))

        # Attach secret_key.txt from string
        secret_part = MIMEApplication(secret_key_content, Name="secret_key.txt")
        secret_part['Content-Disposition'] = 'attachment; filename="secret_key.txt"'
        msg.attach(secret_part)

        # Attach recovery_key.txt from string
        recovery_part = MIMEApplication(recovery_key_content, Name="recovery_key.txt")
        recovery_part['Content-Disposition'] = 'attachment; filename="recovery_key.txt"'
        msg.attach(recovery_part)

        # Send the email
        try:
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(from_email, from_password)
            server.sendmail(from_email, to_email, msg.as_string())
            server.quit()
            print(f"[STATUS] Email sent to {to_email} with RSA and recovery keys.")
        except Exception as e:
            print(f"[ERROR] Failed to send email: {e}")
            raise
