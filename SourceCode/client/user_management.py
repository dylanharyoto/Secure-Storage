from SourceCode.server.server import Server
from SourceCode.shared.utils import check_username_regex, check_password_regex

class UserManagement:
    def __init__(self):
        self.server = Server()
    def register_user_IO(self):
        flag_username, flag_password1, flag_password2 = False, False, False
        username, password1, password2 = None, None, None
        while not (flag_username and flag_password1 and flag_password2):
            if not flag_username:
                username = input('Enter your email address (or type "q" to EXIT):\n> ').strip()
                if username == "q":
                    return None
                if not check_username_regex(username):
                    print('[ERROR] Invalid email format. Please enter a valid email address.')
                    continue
                if self.server.check_username_exists(username):
                    print('[ERROR] Email already exists! Please choose a different one.')
                    continue
                flag_username = True
            elif not flag_password1:
                password1 = input('Enter a password with at least 8 characters (or type "q" to EXIT, "b" to BACK):\n> ').strip()
                if password1 == "q":
                    return None
                if password1 == "b":
                    flag_username = False
                    continue
                if not check_password_regex(password1):
                    print("[ERROR] Password must be at least 8 characters long!")
                    continue
                flag_password1 = True
            elif not flag_password2:
                password2 = input('Confirm your password (or type "q" to EXIT, "b" to BACK):\n> ').strip()
                if password2 == "q":
                    return None
                if password2 == "b":
                    flag_password1 = False
                    continue
                if password2 != password1:
                    print("[ERROR] Passwords do not match! Please try again.")
                    continue
                flag_password2 = True
        client_aes = self.server.register_user(username, password1)
        print(f"[STATUS] Email '{username}' registered successfully!")
        return client_aes

    def login_user_IO(self):
        flag_username, flag_password = False, False
        username = None
        while not (flag_username and flag_password):
            if not flag_username:
                username = input('Enter your email address (or type "q" to EXIT):\n> ').strip()
                if username == "q":
                    return False
                if not check_username_regex(username):
                    print('[ERROR] Invalid email format. Please enter a valid email address.')
                    continue
                if not self.server.check_username_exists(username):
                    print("[ERROR] Email not found. Please try again.")
                    continue
                flag_username = True
            elif not flag_password:
                password = input('Enter your password (or type "q" to EXIT, "b" to BACK):\n> ').strip()
                if password == "q":
                    return False
                if password == "b":
                    flag_username = False
                    break
                if not check_password_regex(password):
                    print("[ERROR] Password must be at least 8 characters long!")
                    continue
                if not self.server.login_user(username, password):
                    print("[ERROR] Incorrect password. Please try again.")
                    continue
                flag_password = True
        print(f"[STATUS] Login successful! Welcome, {username}.")
        return True

    def reset_password_IO(self):
        flag_username, flag_old_password, flag_new_password1, flag_new_password2 = False, False, False, False
        username, old_password, new_password1, new_password2 = None, None, None, None
        while not (flag_username and flag_old_password and flag_new_password1 and flag_new_password2):
            if not flag_username:
                username = input('Enter your email address (or type "q" to EXIT):\n> ').strip()
                if username == "q":
                    return False
                if not check_username_regex(username):
                    print('[ERROR] Invalid email format. Please enter a valid email address.')
                    continue
                if not self.server.check_username_exists(username):
                    print("[ERROR] Email not found. Please try again.")
                    continue
                flag_username = True
            elif not flag_old_password:
                old_password = input('Enter your old password (or type "q" to EXIT, "b" to BACK):\n> ').strip()
                if old_password == "q":
                    return False
                if old_password == "b":
                    flag_username = False
                    continue
                if not self.server.login_user(username, old_password):                
                    print("[ERROR] Incorrect password. Please try again.")
                    continue
                flag_old_password = True
            elif not flag_new_password1:
                new_password1 = input('Enter a new password with at least 8 characters (or type "q" to EXIT, "b" to BACK):\n> ').strip()
                if new_password1 == "q":
                    return False
                if new_password1 == "b":
                    new_password1 = False
                    continue
                if not check_password_regex(new_password1):
                    print("[ERROR] Password must be at least 8 characters long!")
                    continue
                flag_new_password1 = True
            elif not flag_new_password2:
                new_password2 = input('Confirm your new password (or type "q" to EXIT, "b" to BACK):\n> ').strip()
                if new_password2 == "q":
                    return False
                if new_password2 == "b":
                    flag_new_password1 = False
                    continue
                if new_password2 != new_password1:
                    print("[ERROR] Passwords do not match! Please try again.")
                    continue
                flag_new_password2 = True
        self.server.reset_password(username, new_password1)
        print(f"[STATUS] Password for '{username}' has been successfully reset.")
        return True