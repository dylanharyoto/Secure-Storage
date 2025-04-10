import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from SourceCode.Client.ClientIO import ClientIO

log_schema = {
    "log_id": "INTEGER PRIMARY KEY AUTOINCREMENT",
    "timestamp": "TEXT NOT NULL",
    "message": "TEXT"
}
def run():
    while True:
        print("\nUser Management Menu:")
        print("1. Register User")
        print("2. Log In")
        print("3. Reset Password")
        print("4. Exit")
        choice = input("Enter your choice:\n> ").strip()
        if choice == "1":
            status, recovery_key, secret_key = ClientIO.register_user_IO()
            print(f"Recovery key: {str(recovery_key)[2:-1]}")
            secret_key = ''.join(str(secret_key).split("\\n")[1:-1])
            print(f"Recovery key: {secret_key}")
        elif choice == "2":
            status, username, password = ClientIO.login_user_IO()
            if status and username and password:
                session(username, password)
        elif choice == "3":
            status, recovery_key = ClientIO.reset_password_IO()
            print(recovery_key)
        elif choice == "4":
            print("Exiting User Management...")
            break
        else:
            print("[ERROR] Invalid choice. Please try again.")

def session(username, password):
    while True:
        print("\nHome Page:")
        print("1. Check File(s)")
        print("2. Upload File")
        print("3. Download File")
        print("4. Edit File")
        print("5. Delete File")
        print("6. Share File")
        print("7. Log Out")
        choice = input("Enter your choice:\n> ").strip()
        if choice == "1":
            ClientIO.check_file_IO(username)
        elif choice == "2":
            ClientIO.upload_file_IO(username, password)
        elif choice == "3":
            ClientIO.download_file_IO(username, password)
        elif choice == "4":
            ClientIO.edit_file_IO(username, password)
        elif choice == "5":
            ClientIO.delete_file_IO(username)
        elif choice == "6":
            ClientIO.share_file_IO(username)
        elif choice == "7":
            print("User Logging Out...")
            break
        else:
            print("Invalid choice. Please try again.")
    

if __name__ == "__main__":
    run()