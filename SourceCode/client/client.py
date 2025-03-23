from SourceCode.client.user_management import UserManagement
from SourceCode.shared.utils import init_database
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATABASE_FILE = "users.db"

def user_management():
    init_database(DATABASE_FILE)
    while True:
        print("\nUser Management Menu:")
        print("1. Register User")
        print("2. Log In")
        print("3. Reset Password")
        print("4. Exit")
        choice = input("Enter your choice:\n> ").strip()
        if choice == "1":
            client_aes = UserManagement.register_user_IO()
        elif choice == "2":
            status = UserManagement.login_user_IO()
        elif choice == "3":
            status = UserManagement.reset_password_IO()
        elif choice == "4":
            print("Exiting User Management...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    user_management()