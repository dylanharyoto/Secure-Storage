import sqlite3
from SourceCode.shared.utils import check_password, generate_aes, hash_password, split_aes

def register_user(database_file_name):
    conn = sqlite3.connect(database_file_name)
    cursor = conn.cursor()
    flag_username = False
    flag_password1 = False
    flag_password2 = False
    username = None
    password1 = None
    while not (flag_username and flag_password1 and flag_password2):
        if not flag_username:
            username_input = input('Enter a unique username (or type "q" for EXIT):\n> ').strip()
            if username_input == "q":
                conn.close()
                return
            cursor.execute("SELECT * FROM users WHERE username = ?", (username_input,))
            if cursor.fetchone():
                print('[ERROR] Username already exists! Please choose a different one.')
            else:
                username = username_input
                flag_username = True
        elif not flag_password1:
            password1_input = input('Enter a password with at least 8 characters (or type "q" for EXIT, "b" for BACK):\n> ').strip()
            if password1_input == "q":
                conn.close()
                return
            elif password1_input == "b":
                flag_username = False
            elif len(password1_input) < 8:
                print("[ERROR] Password must be at least 8 characters long!")
            else:
                password1 = password1_input
                flag_password1 = True
        elif not flag_password2:
            password2 = input('Confirm your password (or type "q" for EXIT, "b" for BACK):\n> ').strip()
            if password2 == "q":
                conn.close()
                return
            elif password2 == "b":
                flag_password1 = False
            elif password2 != password1:
                print("[ERROR] Passwords do not match! Please try again.")
            else:
                flag_password2 = True
    hashed_password = hash_password(password1)
    aes_key = generate_aes()
    client_key, server_key = split_aes(aes_key)
    cursor.execute("INSERT INTO users (username, password, key) VALUES (?, ?, ?)", (username, hashed_password, server_key))
    conn.commit()
    print(f"[STATUS] Username '{username}' registered successfully!")
    conn.close()

def login_user(database_file_name):
    conn = sqlite3.connect(database_file_name)
    cursor = conn.cursor()
    flag_username = False
    while not flag_username:
        username = input('Enter your username (or type "q" for EXIT):\n> ').strip()
        if username == "q":
            conn.close()
            return
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if not result:
            print("[ERROR] Username not found. Please try again.")
        else:
            hashed_password = result[0]
            flag_username = True
    while flag_username:
        password = input('Enter your password (or type "q" for EXIT, "b" for BACK):\n> ').strip()
        if password == "q":
            conn.close()
            return
        elif password == "b":
            flag_username = False
            break
        if check_password(password, hashed_password):
            print(f"[STATUS] Login successful! Welcome, {username}.")
            conn.close()
            return
        else:
            print("[ERROR] Incorrect password. Please try again.")

def reset_password(database_file_name):
    conn = sqlite3.connect(database_file_name)
    cursor = conn.cursor()
    flag_username, flag_current_password, flag_new_password1, flag_new_password2 = False, False, False, False
    username, stored_password, new_password1 = None, None, None
    while not (flag_username and flag_current_password and flag_new_password1 and flag_new_password2):
        if not flag_username:
            username_input = input('Enter your username (or type "q" for EXIT):\n> ').strip()
            if username_input == "q":
                conn.close()
                return  
            cursor.execute("SELECT password FROM users WHERE username = ?", (username_input,))
            result = cursor.fetchone()
            if result:
                username = username_input
                stored_password = result[0]
                flag_username = True
            else:
                print("[ERROR] Username not found. Please try again.")
        elif not flag_current_password:
            current_password = input('Enter your current password (or type "q" for EXIT, "b" for BACK):\n> ').strip()
            if current_password == "q":
                conn.close()
                return
            elif current_password == "b":
                flag_username = False  
            elif check_password(current_password, stored_password):
                flag_current_password = True
            else:
                print("[ERROR] Incorrect password. Please try again.")
        elif not flag_new_password1:
            new_password_input = input('Enter a new password with at least 8 characters (or type "q" for EXIT, "b" for BACK):\n> ').strip()
            if new_password_input == "q":
                conn.close()
                return
            elif new_password_input == "b":
                flag_current_password = False  
            elif len(new_password_input) < 8:
                print("[ERROR] Password must be at least 8 characters long!")
            else:
                new_password1 = new_password_input
                flag_new_password1 = True
        elif not flag_new_password2:
            new_password2 = input('Confirm your new password (or type "q" for EXIT, "b" for BACK):\n> ').strip()
            if new_password2 == "q":
                conn.close()
                return
            elif new_password2 == "b":
                flag_new_password1 = False 
            elif new_password2 != new_password1:
                print("[ERROR] Passwords do not match! Please try again.")
            else:
                flag_new_password2 = True
    hashed_new_password = hash_password(new_password1)
    cursor.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_new_password, username))
    conn.commit()
    print(f"[STATUS] Password for '{username}' has been successfully reset.")
    conn.close()
