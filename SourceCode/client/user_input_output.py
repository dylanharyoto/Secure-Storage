import requests
import os
from SourceCode.shared.utils import check_username_regex, check_password_regex, generate_aes, hash_password, split_aes
from encryption import AES_encrypt, generate_rsa_keys, encrypt_file, decrypt_file, encrypt_file_for_sharing, decrypt_shared_file, recover_key_check

class User_Iuput_Output:
    def __init__(self):
        self.server_url = "http://localhost:5200"  # Adjust if the server runs on a different host/port

    def register_user_IO(self):
        flag_username, flag_password1, flag_password2 = False, False, False
        username, password1, password2 = None, None, None
        while not (flag_username and flag_password1 and flag_password2):
            if not flag_username:
                username = input('Enter your email address (or type "q" to EXIT):\n> ').strip()
                if username == "q":
                    return None
                if not check_username_regex(username):
                    print('[ERROR] Invalid email format.')
                    continue
                try:
                    response = requests.post(f"{self.server_url}/check_username", json={"username": username})
                    if response.status_code == 200:
                        flag_username = True # next step
                    elif response.status_code == 201:
                        print('[ERROR] Email already exists.')
                    else:
                        print("[ERROR] Server error.")
                except requests.exceptions.RequestException as e:
                    print(f"[ERROR] Network error: {e}.")
                    continue
            elif not flag_password1:
                password1 = input('Enter a password with at least 8 characters (or type "q" to EXIT, "b" to BACK):\n> ').strip()
                if password1 == "q":
                    return None
                if password1 == "b":
                    flag_username = False
                    continue
                if not check_password_regex(password1):
                    print("[ERROR] Password must be at least 8 characters long.")
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
                    print("[ERROR] Passwords do not match.")
                    continue
                try:
                    encrypted_combined_key, recover_key = AES_encrypt(password1)
                    sk, pk = generate_rsa_keys()
                    response = requests.post(f"{self.server_url}/register", json={"username": username, "password": password1, 
                                                                                  "aes": encrypted_combined_key, "rsa": pk})
                    if response.status_code == 200:
                        flag_password2 = True
                        print(f"[STATUS] Email '{username}' registered successfully.")
                        return recover_key, sk
                    else:
                        print("[ERROR] Server error.")
                        return False
                except requests.exceptions.RequestException as e:
                    print(f"[ERROR] Network error: {e}.")
                    return False
        return True

    def login_user_IO(self):
        flag_username, flag_password = False, False
        username = None
        while not (flag_username and flag_password):
            if not flag_username:
                username = input('Enter your email address (or type "q" to EXIT):\n> ').strip()
                if username == "q":
                    return False
                if not check_username_regex(username):
                    print('[ERROR] Invalid email format.')
                    continue
                try:
                    response = requests.post(f"{self.server_url}/check_username", json={"username": username})
                    if response.status_code == 200:
                        print("[ERROR] Email not found.")
                    elif response.status_code == 201:
                        flag_username = True
                    else:
                        print("[ERROR] Server error.")
                        return False
                except requests.exceptions.RequestException as e:
                    print(f"[ERROR] Network error: {e}.")
                    return False
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
                try:
                    response = requests.post(f"{self.server_url}/login", json={"username": username, "password": password})
                    if response.status_code == 200:
                        flag_password = True
                    elif response.status_code == 201:
                        print("[ERROR] Incorrect password.")
                    else:
                        print("[ERROR] Server error.")
                        return False
                except requests.exceptions.RequestException as e:
                    print(f"[ERROR] Network error: {e}.")
                    return False
        return True, username, password

    def reset_password_IO(self):
        flag_username, flag_recover_key, flag_new_password1, flag_new_password2 = False, False, False, False
        username, recover_key, new_password1, new_password2 = None, None, None, None
        while not (flag_username and flag_recover_key and flag_new_password1 and flag_new_password2):
            if not flag_username:
                username = input('Enter your email address (or type "q" to EXIT):\n> ').strip()
                if username == "q":
                    return False
                if not check_username_regex(username):
                    print('[ERROR] Invalid email format.')
                    continue
                try:
                    response = requests.post(f"{self.server_url}/check_username", json={"username": username})
                    if response.status_code == 200:
                        print("[ERROR] Email not found.")
                        continue
                    elif response.status_code == 201:
                        flag_username = True
                    else:
                        print("[ERROR] Server error")
                        return False
                except requests.exceptions.RequestException as e:
                    print(f"[ERROR] Network error: {e}")
                    return False
            elif not flag_recover_key:
                recover_key = input('Enter your recover key (or type "q" to EXIT, "b" to BACK):\n> ').strip()
                if recover_key == "q":
                    return False
                if recover_key == "b":
                    flag_username = False
                    continue
                try:
                    response = requests.post(f"{self.server_url}/require_aes", json={"username": username})
                    if response.status_code == 200:
                        user_aes = response.json()['aes']
                        key_check = recover_key_check(recover_key, user_aes)
                        if key_check[0]:
                            flag_recover_key = True
                            aes_plaintext = key_check[1]
                    elif response.status_code == 400:
                        print(f"[ERROR] {response.json()["error"]}")
                        continue
                    else:
                        print("[ERROR] Server error")
                        return False
                except requests.exceptions.RequestException as e:
                    print(f"[ERROR] Network error: {e}")     
                    return False    
            
            # User passed the authentication test, now is able to reset the password
            if not flag_new_password1:
                new_password1 = input('Enter a new password with at least 8 characters (or type "q" to EXIT):\n> ').strip()
                if new_password1 == "q":
                    return False
                if not check_password_regex(new_password1):
                    print("[ERROR] Password must be at least 8 characters long.")
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
                    print("[ERROR] Passwords do not match.")
                    continue

                

                try:
                    encrypted_combined_key, recover_key = AES_encrypt(new_password1, aes_plaintext)


                    if response.status_code == 200:
                        flag_password2 = True
                        print(f"[STATUS] Email '{username}' registered successfully.")
                        return recover_key, sk
                    else:
                        print("[ERROR] Server error.")
                        return False
                except requests.exceptions.RequestException as e:
                    print(f"[ERROR] Network error: {e}.")
                    return False

        return True
    
    
    
    def upload_file(self, username, password):
        """
        Encrypt and upload a file to the server
        """
        file_path = input("Please input the path of the file to be uploaded (or type \"q\" to EXIT):\n> ")
        if file_path == 'q':
            return None
        
        if os.path.isfile(file_path):
            file_name = os.path.basename(file_path)
            # Encrypt the target file and store cipher text into temp file
            encry_file_path = os.path.join("temp", file_name)
            # Get user's encrypted aes key from server
            data = {'username': username}
            try:
                response = requests.post(f"{self.server_url}/require_aes", data=data)
            except requests.exceptions.RequestException as e:
                print(f"[ERROR] Network error: {e}.")
                return None
            user_aes = response.json()['aes']
            # Process original file and make a temp new file, store the path of new into encry_file_path
            encrypt_file(password, user_aes, file_path, encry_file_path)

            # Open the temp file and send to server
            with open(encry_file_path, 'rb') as file:
                files = {'file': file}
            try:
                    response = requests.post(f"{self.server_url}/upload", files=files, data=data)
                    if response.status_code == 400:
                        print(f"[ERROR] {response.json()["error"]}")
                        return None
                    # Remove the temp file
                    os.remove(encry_file_path)
                    return response.json()
            except requests.exceptions.RequestException as e:
                print(f"[ERROR] Network error: {e}.")
                return None
        print("[ERROR] Invalid file path or file does not exist.")

    def edit_file(self, username, password):
        """
        Update the target file by sending new content to server
        """
        # file flag tests if user has already input a target file, and path flag tests if user finish process
        path_flag = False
        file_flag = False
        file_id = 0
        while not path_flag:
            try:
                # Query user for the file id of file to be edited
                if not file_flag:
                    choice = input("Please input the file ID for the file to be edited (or type \"q\" to EXIT):\n> ")
                    if choice == 'q':
                        return None
                    file_id = int(choice)
                file_flag = True

                # Query user for local file to replace
                choice = input("Please input the path of the file to be edited  (or type \"q\" to EXIT, \"b\" to BACK):\n> :\n> ")
                if choice == "q":
                    return None
                # Re-enter target file
                if choice == "b":
                    file_flag = False
                    continue
                file_path = choice
                if os.path.isfile(file_path):
                    
                    file_name = os.path.basename(file_path)
                    # Encrypt the target file and store cipher text into temp file
                    encry_file_path = os.path.join("temp", file_name)
                    # Get user's encrypted aes key from server
                    data = {'username': username}
                    try:
                        response = requests.post(f"{self.server_url}/require_aes", data=data)
                        if response.status_code == 400:
                            print(f"[ERROR] {response.json()["error"]}")
                            return None
                    except requests.exceptions.RequestException as e:
                        print(f"[ERROR] Network error: {e}.")
                        return None
                    user_aes = response.json()['aes']
                    # Process original file and make a temp new file, store the path of new into encry_file_path
                    encrypt_file(password, user_aes, file_path, encry_file_path)

                    # Open the temp file and send to server
                    with open(encry_file_path, 'rb') as file:
                        new_content = {'file': file}

                    # Request for the file content from server
                    data = {'username': username, 'file_id': file_id, 'content': new_content}
                    response = requests.post(f"{self.server_url}/edit", json=data)
                    if response.status_code == 403:
                        print(f"[ERROR] {response.json()["error"]}")
                        return None
                    # Remove the temp file
                    os.remove(encry_file_path)
                    return response.json()
                print("[ERROR] Invalid file path or file does not exist.")
            
            except ValueError:
                print("[ERROR] Please input a valid integer")
            except requests.exceptions.RequestException as e:
                print(f"[ERROR] Network error: {e}.")
                return None

    def delete_file(self, username):
        """
        Delete the target file from server storage
        """
        try:
            # Query user for the file id of file to be deleted
            choice = input("Please input the file ID for the file to be edited (or type \"q\" to EXIT):\n> ")
            if choice == 'q':
                return None
            file_id = int(choice)
            data = {'username': username, 'file_id': file_id}
            response = requests.post(f"{self.server_url}/delete", json=data)

            if response.status_code == 403:
                print(f"[ERROR] {response.json()["error"]}")
                return None
            return response.json()
            
        except ValueError:
            print("[ERROR] Please input a valid integer")
            return None
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Network error: {e}.")
            return None
    
    def share_users(self, username):
        """
        Fetch all users available and allow current user to choose those to share with
        Then send information to server
        """
        # file flag tests if user has already input a target file, and user flag tests if user finish process
        user_flag = False
        file_flag = False
        file_id = 0
        user_names = []

        # Fetch all existing users from server
        try:
            response = requests.post(f"{self.server_url}/get_users")
            message = response.json()["message"]

            ####ERROR

            all_users = message.split(',').sort()
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Network error: {e}.")
            return None
        
        while not user_flag:
            # Query user for the file id of file to be shared
            if not file_flag:
                choice = input("Please input the file ID for the file to be shared (or type \"q\" to EXIT):\n> ")
                if choice == 'q':
                    return None
                try:
                    file_id = int(choice)
                except ValueError:
                    print("[ERROR] Please input a valid integer")
                    continue
            file_flag = True

            # list all users available to share
            print("Other current users available are listed below:")
            [print(f"{i+1}: {all_users[i]}") for i in range(len(all_users)) if username != all_users[i]]
            if len(user_names)==0:
                print(f"Added users are: None")
            else:
                print(f"Added users are: {','.join(user_names)}")

            # Query user to choose a user to share
            choice = input("Please input one correspond index of target user to share with,\ntype \"p\" to proceed (or type \"q\" to EXIT, \"b\" to BACK):\n> ")
            if choice == "q":
                return None
            # Re-enter target file
            if choice == "b":
                if user_names:
                    all_users.append(user_names.pop())
                    all_users = all_users.sort()
                else:
                    file_flag = False
                continue
            # proceed to send all selected users to server
            if choice == "p":
                try:

                    ##############################################################
                    # Server return the encrypted file, and all pk for the users #
                    ##############################################################

                    data = {'username': username, 'file_id': file_id, 'users': user_names}
                    response = requests.post(f"{self.server_url}/share", json=data)

                    
                    
                    return response.json()
                except requests.exceptions.RequestException as e:
                    print(f"[ERROR] Network error: {e}.")
                    return None
            try:
                user_names.append(all_users[int(choice)])
            except ValueError:
                print("[ERROR] Please input a valid integer")
                continue
            except IndexError:
                print("[ERROR] Please input a valid user index")
                continue
    def download_file(self, username, password):
        """
        Download an existing file from the server to a specific directory.
        """
        # Query user for the target file id
        input_flag = False
        while not input_flag:
            try:
                choice = input("Please input the file ID for the file to be downloaded (or type \"q\" to EXIT):\n> ")
                if choice == 'q':
                    return None
                file_id = int(choice)

                # Request for the file content from server
                data = {'username': username, 'file_id': file_id}
                response = requests.post(f"{self.server_url}/get", json=data)
                if response.status_code == 403:
                        print(f"[ERROR] {response.json()["error"]}")
                        return None
                return response.json()
            
            except ValueError:
                print("[ERROR] Please input a valid integer")
            except requests.exceptions.RequestException as e:
                print(f"[ERROR] Network error: {e}.")
                return None
        
    def user_read_storage(self, username):
        """
        Fetch all file names in the storages that this client can read.
        """
        try:
            response = requests.post(f"{self.server_url}/view_files", json={"username": username})

            #Print out existing files with id
            if response.status_code == 200:
                print(response.json()["message"])
            else:
                print("[ERROR] Server error.")
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Network error: {e}.")
