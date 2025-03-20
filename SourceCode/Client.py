import sqlite3
import re
import bcrypt

DATABASE_FILE = "comp3334.db"
def init_database():
    conn = sqlite3.connect(DATABASE_FILE);
    cursor = conn.cursor();
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            key TEXT NOT NULL
            )
    ''')
    conn.commit()
    conn.close()

def hash_password(input_password):
    return bcrypt.hashpw(input_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def check_password(input_password, hashed_password):
    return bcrypt.checkpw(input_password.encode("utf-8"), hashed_password.encode("utf-8"))

def register_user():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    while True:
        username = input("Enter a unique username: ").strip()
        if username == "q":
            conn.close()
            return 
        cursor.execute("SELECT * FROM users WHERE username = ?", (username, ))
        if cursor.fetchone():
            print("[ERROR] Username already exists. Please choose a different one, or type \"q\" to exit. ")
        else:
            break
    while True:
        password1 = input("Enter a password (at least 8 characters, containing only A-Z, a-z, 0-9, @#$%^&+=): ").strip()
        if not re.fullmatch(r'.{8,}', password1):
            print("[ERROR] Password must be at least 8 characters long.")
        else:
            break
    while True:
        password2 = input("Confirm your password: ").strip()
        if password1 != password2:
            print("[ERROR] Passwords do not match. Please try again.")
        else:
            break
    hashedPassword = hash_password(password1)
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashedPassword))
    conn.commit()
    print("[STATUS] Username '{0}' registered successfully!".format(username))
    conn.close()

def userManagement():
    while True:
        print("\nUser Management Menu:")
        print("1. Register User")
        print("2. Log In")
        print("3. Reset Password")
        print("4. Exit")
        choice = input("Enter your choice: ").strip()
        if choice == "1":
            registerUser()
        elif choice == "2":
            # login_user()
            return
        elif choice == "3":
            # reset_password()
            return
        elif choice == "4":
            print("Exiting User Management.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    userManagement()
