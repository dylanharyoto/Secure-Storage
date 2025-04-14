import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from sourcecode.Client.ClientIO import ClientIO
from sourcecode.Server import config

ADMIN_USER = config.ADMIN_USER

def run():
    """
    Displays the user management menu and handles user actions such as 
    registration, login, and password reset.

    This function operates in a loop, allowing users to select options 
    until they choose to exit.
    """
    while True:
        print("\nUser Management Menu:")
        print("1. Register User")
        print("2. Log In")
        print("3. Reset Password")
        print("4. Exit")
        choice = input("Enter your choice:\n> ").strip()
        
        # Handle user choices
        if choice == "1":
            ClientIO.register_user_IO()  # Call to register a new user
        elif choice == "2":
            # Call to log in and retrieve session details
            status, username, password = ClientIO.login_user_IO()
            if status and username and password:
                session(username, password)  # Enter user session if successful
        elif choice == "3":
            ClientIO.reset_password_IO()  # Call to reset user password
        elif choice == "4":
            print("Exiting User Management...")
            break  # Exit the loop and end the program
        else:
            print("[ERROR] Invalid choice. Please try again.")  # Handle invalid input

def session(username, password):
    """
    Manages the user session, allowing users to interact with file operations 
    such as checking, uploading, downloading, editing, deleting, and sharing files.

    Parameters:
    - username: The username of the logged-in user.
    - password: The password of the logged-in user.

    This function operates in a loop, allowing the user to select file operations 
    until they log out.
    """
    while True:
        print("\nHome Page:")
        print("1. Check File(s)")
        print("2. Upload File")
        print("3. Download File")
        print("4. Edit File")
        print("5. Delete File")
        print("6. Share File")
        
        # Display additional options for admin users
        if username == ADMIN_USER:
            print("7. Check Logs")
            print("8. Log Out")
        else:
            print("7. Log Out")
        
        choice = input("Enter your choice:\n> ").strip()
        
        # Handle file operation choices
        if choice == "1":
            ClientIO.check_file_IO(username)  # Check files available to the user
        elif choice == "2":
            ClientIO.upload_file_IO(username, password)  # Upload a file
        elif choice == "3":
            ClientIO.download_file_IO(username, password)  # Download a file
        elif choice == "4":
            ClientIO.edit_file_IO(username, password)  # Edit a file
        elif choice == "5":
            ClientIO.delete_file_IO(username)  # Delete a file
        elif choice == "6":
            ClientIO.share_file_IO(username, password)  # Share a file
        elif choice == "7":
            if username == ADMIN_USER:
                ClientIO.view_logs_IO(username)  # Admin view logs
            else:
                print("User Logging Out...")
                break  # Log out for regular users
        elif choice == "8" and username == ADMIN_USER:
            print("User Logging Out...")
            break  # Log out for admin users
        else:
            print("Invalid choice. Please try again.")  # Handle invalid input

if __name__ == "__main__":
    run()  # Start the user management program