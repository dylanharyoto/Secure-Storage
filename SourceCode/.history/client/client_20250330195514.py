import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from SourceCode.client.user_management import UserManagement

class Client:
    def __init__(self):
        self.user_management = UserManagement()

    def run(self):
        while True:
            print("\nUser Management Menu:")
            print("1. Register User")
            print("2. Log In")
            print("3. Reset Password")
            print("4. Exit")
            choice = input("Enter your choice:\n> ").strip()
            if choice == "1":
                client_aes = self.user_management.register_user_IO()
                if client_aes:
                    print(f"[INFO] Client AES key generated: {client_aes}")
            elif choice == "2":
                status = self.user_management.login_user_IO()
                if status:
                    print("[INFO] Login successful.")
            elif choice == "3":
                status = self.user_management.reset_password_IO()
                if status:
                    print("[INFO] Password reset successful.")
            elif choice == "4":
                print("Exiting User Management...")
                break
            else:
                print("Invalid choice. Please try again.")

if __name__ == "__main__":
    client = Client()
    client.run()