import sqlite3
import re
import bcrypt

DATABASE_FILE = "Users.db"

def init_database():
    # Initialize the database and create the users table if it does not exist
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def hash_password(input_password):
    # Hash a password using bcrypt
    return bcrypt.hashpw(input_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def check_password(input_password, hashed_password):
    # Verify a password against a stored hash
    return bcrypt.checkpw(input_password.encode("utf-8"), hashed_password.encode("utf-8"))

def register_user():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    flag_username, flag_password1, flag_password2 = False, False, False
    while (not flag_username) and (not flag_password1) and (not flag_password2):
        while (not flag_username):
            username = input('Enter a unique username (or type "q" for EXIT):\n> ').strip()
            if username == "q":
                conn.close()
                return
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                print('[ERROR] Username already exists! Please choose a different one.')
            else:
                flag_username = True  
        while flag_username and (not flag_password1):
            password1 = input('Enter a password with at least 8 characters (or type "q" for EXIT, "b" for BACK):\n> ').strip()
            if password1 == "q": 
                conn.close()
                return
            elif password1 == "b":  
                conn.close()
                flag_username = False
                break
            # Validate password length
            if not re.fullmatch(r".{8,}", password1):
                print("[ERROR] Password must be at least 8 characters long!")
            else:
                flag_password1 = True
        while flag_username and flag_password1 and (not flag_password2):
            password2 = input('Confirm your password (or type "q" for EXIT, "b" for BACK):\n> ').strip()
            if password2 == "q": 
                conn.close()
                return
            elif password2 == "b": 
                conn.close()
                flag_password1 = False
                break
            # Check if passwords match
            if password1 != password2:
                print("[ERROR] Passwords do not match! Please try again.")
            else:
                flag_password2 = True

    # Hash the password and insert the user into the database
    hashed_password = hash_password(password1)
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
    conn.commit()
    print(f"[STATUS] Username '{username}' registered successfully!")
    conn.close()

def login_user():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    while True:
        username = input('Enter your username (or type "q" for EXIT, "b" for BACK):\n> ').strip()
        if username == "q":  # Exit login
            conn.close()
            return
        elif username == "b":  # Go back to the main menu
            conn.close()
            return "back"

        # Fetch the user from the database
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if not result:
            print("[ERROR] Username not found. Please try again.")
        else:
            break  # Username exists, proceed to password input

    while True:
        password = input('Enter your password (or type "q" for EXIT, "b" for BACK):\n> ').strip()
        if password == "q":  # Exit login
            conn.close()
            return
        elif password == "b":  # Go back to the main menu
            conn.close()
            return "back"

        # Verify the password
        hashed_password = result[0]
        if check_password(password, hashed_password):
            print(f"[STATUS] Login successful! Welcome, {username}.")
            conn.close()
            return
        else:
            print("[ERROR] Incorrect password. Please try again.")

def user_management():
    init_database()
    while True:
        print("\nUser Management Menu:")
        print("1. Register User")
        print("2. Log In")
        print("3. Reset Password")
        print("4. Exit")
        choice = input("Enter your choice:\n> ").strip()

        if choice == "1":
            result = register_user()
            if result == "back":  # Handle "b" (BACK) from register_user
                continue
        elif choice == "2":
            result = login_user()
            if result == "back":  # Handle "b" (BACK) from login_user
                continue
        elif choice == "3":
            # Placeholder for reset_password function
            print("[INFO] Reset Password functionality is not implemented yet.")
            continue
        elif choice == "4":
            print("Exiting User Management.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    user_management()