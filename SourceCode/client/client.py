import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from SourceCode.client.user_input_output import User_Iuput_Output

class Client:
    def __init__(self):
        self.user_input_output = User_Iuput_Output()
        self.run()

    def run(self):
        while True:
            print("\nUser Management Menu:")
            print("1. Register User")
            print("2. Log In")
            print("3. Reset Password")
            print("4. Exit")
            choice = input("Enter your choice:\n> ").strip()
            if choice == "1":
                client_aes = self.user_input_output.register_user_IO()
                if client_aes:
                    print(f"[INFO] Client AES key generated: {client_aes}")
            elif choice == "2":
                status, username, password = self.user_input_output.login_user_IO()
                if status:
                    print("[INFO] Login successful.")
                    self.session(username, password)
            elif choice == "3":
                status = self.user_input_output.reset_password_IO()
                if status:
                    print("[INFO] Password reset successful.")
            elif choice == "4":
                print("Exiting User Management...")
                break
            else:
                print("Invalid choice. Please try again.")
    
    
    def session(self, username, password):
        while True:
            print("\nHome Page:")
            print("1. View Storage")
            print("2. Upload File")
            print("3. Download File")
            print("4. Edit File")
            print("5. Delete File")
            print("6. Share File")
            print("7. Log Out")
            choice = input("Enter your choice:\n> ").strip()
            if choice == "1":
                self.user_input_output.user_read_storage(username)
            elif choice == "2":
                self.user_input_output.upload_file(username, password)
            elif choice == "3":
                self.user_input_output.download_file(username, password)
            elif choice == "4":
                self.user_input_output.edit_file(username, password)
            elif choice == "5":
                self.user_input_output.delete_file(username)
            elif choice == "6":
                self.user_input_output.share_users(username)
            elif choice == "7":
                print("User Logging Out...")
                break
            else:
                print("Invalid choice. Please try again.")
    

if __name__ == "__main__":
    client = Client()