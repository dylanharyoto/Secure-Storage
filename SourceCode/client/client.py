from SourceCode.server.user_management import register_user_IO, login_user_IO, reset_password_IO
from SourceCode.shared.utils import init_database

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
            register_user_IO()
        elif choice == "2":
            login_user_IO()
        elif choice == "3":
            reset_password_IO()
        elif choice == "4":
            print("Exiting User Management...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    user_management()