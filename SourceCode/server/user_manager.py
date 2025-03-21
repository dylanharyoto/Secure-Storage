import sqlite3
from SourceCode.shared.utils import check_password, hash_password, is_valid_email, is_valid_password


def register_user(database_file_name):
    conn = sqlite3.connect(database_file_name)
    cursor = conn.cursor()
    flag_email = False
    flag_password1 = False
    flag_password2 = False
    email = None
    password1 = None
    while not (flag_email and flag_password1 and flag_password2):
        if not flag_email:
            email_input = input('Enter a unique email address (or type "q" for EXIT):\n> ').strip()
            if email_input == "q":
                conn.close()
                return
            if not is_valid_email(email_input):
                print('[ERROR] Invalid email format. Please enter a valid email address.')
                continue
            cursor.execute("SELECT * FROM users WHERE email = ?", (email_input,))
            if cursor.fetchone():
                print('[ERROR] Email already exists! Please choose a different one.')
            else:
                email = email_input
                flag_email = True
        elif not flag_password1:
            password1 = input('Enter a password with at least 8 characters (or type "q" for EXIT, "b" for BACK):\n> ').strip()
            if password1 == "q":
                conn.close()
                return
            elif password1 == "b":
                flag_email = False
            # Up and down serve different purposes (separate if statement)
            if not is_valid_password(password1):
                print("[ERROR] Password must be at least 8 characters long!")
            else:
                flag_password1 = True
        elif not flag_password2:
            password2 = input('Confirm your password (or type "q" for EXIT, "b" for BACK):\n> ').strip()
            if password2 == "q":
                conn.close()
                return
            elif password2 == "b":
                flag_password1 = False
            # Up and down serve different purposes (separate if statement)
            if password2 != password1:
                print("[ERROR] Passwords do not match! Please try again.")
            else:
                flag_password2 = True
    hashed_password = hash_password(password1)
    cursor.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed_password))
    conn.commit()
    print(f"[STATUS] Email '{email}' registered successfully!")
    conn.close()

def login_user(database_file_name):
    conn = sqlite3.connect(database_file_name)
    cursor = conn.cursor()
    flag_email = False
    while not flag_email:
        email_input = input('Enter your email address (or type "q" for EXIT):\n> ').strip()
        if email_input == "q":
            conn.close()
            return
        if not is_valid_email(email_input):
            print('[ERROR] Invalid email format. Please enter a valid email address.')
            continue
        cursor.execute("SELECT password FROM users WHERE email = ?", (email_input,))
        result = cursor.fetchone()
        if not result:
            print("[ERROR] Email not found. Please try again.")
        else:
            hashed_password = result[0]
            flag_email = True
    while flag_email:
        password = input('Enter your password (or type "q" for EXIT, "b" for BACK):\n> ').strip()
        if password == "q":
            conn.close()
            return
        elif password == "b":
            flag_email = False
            break
        # Up and down serve different purposes (separate if statement)
        if check_password(password, hashed_password):
            print(f"[STATUS] Login successful! Welcome, {email_input}.")
            conn.close()
            return
        else:
            print("[ERROR] Incorrect password. Please try again.")

def reset_password(database_file_name):
    conn = sqlite3.connect(database_file_name)
    cursor = conn.cursor()
    flag_email, flag_current_password, flag_new_password1, flag_new_password2 = False, False, False, False
    email, stored_password, new_password1 = None, None, None
    while not (flag_email and flag_current_password and flag_new_password1 and flag_new_password2):
        if not flag_email:
            email_input = input('Enter your email address (or type "q" for EXIT):\n> ').strip()
            if email_input == "q":
                conn.close()
                return
            if not is_valid_email(email_input):
                print('[ERROR] Invalid email format. Please enter a valid email address.')
                continue
            cursor.execute("SELECT password FROM users WHERE email = ?", (email_input,))
            result = cursor.fetchone()
            if result:
                email = email_input
                stored_password = result[0]
                flag_email = True
            else:
                print("[ERROR] Email not found. Please try again.")
        elif not flag_current_password:
            current_password = input('Enter your current password (or type "q" for EXIT, "b" for BACK):\n> ').strip()
            if current_password == "q":
                conn.close()
                return
            elif current_password == "b":
                flag_email = False
            # Up and down serve different purposes (separate if statement)
            if check_password(current_password, stored_password):
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
            # Up and down serve different purposes (separate if statement)
            if not is_valid_password(new_password_input):
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
            # Up and down serve different purposes (separate if statement)
            if new_password2 != new_password1:
                print("[ERROR] Passwords do not match! Please try again.")
            else:
                flag_new_password2 = True
    hashed_new_password = hash_password(new_password1)
    cursor.execute("UPDATE users SET password = ? WHERE email = ?", (hashed_new_password, email))
    conn.commit()
    print(f"[STATUS] Password for '{email}' has been successfully reset.")
    conn.close()