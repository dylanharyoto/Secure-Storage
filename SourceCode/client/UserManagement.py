import requests
import os
from SourceCode.Shared import Utils
from SourceCode.Client import CryptoManager


SERVER_URL = os.getenv("SERVER_URL", "http://localhost:5080")
class UserManagement:
    @staticmethod
    def register_user_IO():
        flag_username = False
        flag_password1 = False
        flag_password2 = False
        username = None
        password1 = None
        password2 = None
        encrypted_aes_key = None
        recovery_key = None
        secret_key = None
        public_key = None        
        while not (flag_username and flag_password1 and flag_password2):
            if not flag_username:
                username = input('Enter your email address (or type "q" to EXIT):\n> ').strip()
                if username == "q":
                    return False, None, None
                if not Utils.check_username_regex(username):
                    print('[ERROR] Invalid email format.')
                    continue
                try:
                    response = requests.post(f"{SERVER_URL}/check_username", json={"username": username})
                    if response.status_code == 201:
                        print('[ERROR] Email already exists.')
                    elif response.status_code == None:
                        print("[ERROR] Server error.")
                except requests.exceptions.RequestException as error:
                    print(f"[ERROR] Network error: {error}.")
                    continue
                flag_username = True
            if not flag_password1:
                password1 = input('Enter a password with at least 8 characters (or type "q" to EXIT, "b" to BACK):\n> ').strip()
                if password1 == "q":
                    return False, None, None
                if password1 == "b":
                    flag_username = False
                    continue
                if not Utils.check_password_regex(password1):
                    print("[ERROR] Password must be at least 8 characters long.")
                    continue
                flag_password1 = True
            if not flag_password2:
                password2 = input('Confirm your password (or type "q" to EXIT, "b" to BACK):\n> ').strip()
                if password2 == "q":
                    return False, None, None
                if password2 == "b":
                    flag_password1 = False
                    continue
                if password2 != password1:
                    print("[ERROR] Passwords do not match.")
                    continue
                flag_password2 = True
        try:
            encrypted_aes_key, recovery_key = CryptoManager.encrypt_with_aes(password1)
            secret_key, public_key = CryptoManager.generate_rsa_key_pair()
            hashed_password = CryptoManager.hash_password(password1)
            response = requests.post(f"{SERVER_URL}/register_user", json={"username": username, "password": hashed_password, "encrypted_aes_key": encrypted_aes_key, "public_key": public_key})
            if response.status_code == 200:
                print(f"[STATUS] Email '{username}' registered successfully.")
            else:
                print("[ERROR] Server error.")
                return False, None, None
        except requests.exceptions.RequestException as error:
            print(f"[ERROR] Network error: {error}.")
            return False, None, None
        return True, recovery_key, secret_key
    @staticmethod
    def login_user_IO():
        flag_username = False
        flag_password = False
        username = None
        password = None
        while not (flag_username and flag_password):
            if not flag_username:
                username = input('Enter your email address (or type "q" to EXIT):\n> ').strip()
                if username == "q":
                    return False, None, None
                if not Utils.check_username_regex(username):
                    print('[ERROR] Invalid email format.')
                    continue
                try:
                    response = requests.post(f"{SERVER_URL}/check_username", json={"username": username})
                    if response.status_code == 200:
                        print("[ERROR] Email not found.")
                    elif response.status_code == None:
                        print("[ERROR] Server error.")
                        return False, None, None
                except requests.exceptions.RequestException as error:
                    print(f"[ERROR] Network error: {error}.")
                    return False, None, None
                flag_username = True
            if not flag_password:
                password = input('Enter your password (or type "q" to EXIT, "b" to BACK):\n> ').strip()
                if password == "q":
                    return False, None, None
                if password == "b":
                    flag_username = False
                    continue
                if not Utils.check_password_regex(password):
                    print("[ERROR] Password must be at least 8 characters long!")
                    continue
                flag_password = True
            try:
                hashed_password = CryptoManager.hash_password(password)
                response = requests.post(f"{SERVER_URL}/login_user", json={"username": username, "password": hashed_password})
                if response.status_code == 200:
                    flag_password = True
                    print(f"[STATUS] Email '{username}' logged in successfully.")
                elif response.status_code == 201:
                    flag_password = False
                    print("[ERROR] Incorrect password.")
                else:
                    print("[ERROR] Server error.")
                    return False, None, None
            except requests.exceptions.RequestException as error:
                print(f"[ERROR] Network error: {error}.")
                return False, None, None
        return True, username, password
    @staticmethod
    def reset_password_IO():
        flag_username = False
        flag_recovery_key = False
        flag_new_password1 = False
        flag_new_password2 = False
        username = None
        recovery_key = None
        new_password1 = None
        new_password2 = None
        while not (flag_username and flag_recovery_key and flag_new_password1 and flag_new_password2):
            if not flag_username:
                username = input('Enter your email address (or type "q" to EXIT):\n> ').strip()
                if username == "q":
                    return False, None
                if not Utils.check_username_regex(username):
                    print('[ERROR] Invalid email format.')
                    continue
                try:
                    response = requests.post(f"{SERVER_URL}/check_username", json={"username": username})
                    if response.status_code == 200:
                        print("[ERROR] Email not found.")
                        continue
                    elif response.status_code == None:
                        print("[ERROR] Server error")
                        return False, None
                except requests.exceptions.RequestException as error:
                    print(f"[ERROR] Network error: {error}")
                    return False, None
                flag_username = True
            if not flag_recovery_key:
                recovery_key = input('Enter your recovery key (or type "q" to EXIT, "b" to BACK):\n> ').strip()
                if recovery_key == "q":
                    return False, None
                if recovery_key == "b":
                    flag_username = False
                    continue
                try:
                    response = requests.post(f"{SERVER_URL}/get_aes", json={"username": username})
                    if response.status_code == 200:
                        user_aes_key = response.json()['aes']
                        key_verification_result = CryptoManager.verify_recovery_key(recovery_key, user_aes_key)
                        if key_verification_result[0]:
                            verified_recovery_key = key_verification_result[1]
                        else:
                            print("[ERROR] Validation failed. Recovery key is incorrect.")
                            continue
                    elif response.status_code == 400:
                        error = response.json()["error"]
                        print(f"[ERROR] {error}")
                        continue
                    elif response.status_code == None:
                        print("[ERROR] Server error")
                        return False, None
                except requests.exceptions.RequestException as error:
                    print(f"[ERROR] Network error: {error}")     
                    return False, None
                flag_recovery_key = True
            if not flag_new_password1:
                new_password1 = input('Enter a new password with at least 8 characters (or type "q" to EXIT):\n> ').strip()
                if new_password1 == "q":
                    return False, None
                if not Utils.check_password_regex(new_password1):
                    print("[ERROR] Password must be at least 8 characters long.")
                    continue
                flag_new_password1 = True
            if not flag_new_password2:
                new_password2 = input('Confirm your new password (or type "q" to EXIT, "b" to BACK):\n> ').strip()
                if new_password2 == "q":
                    return False, None
                if new_password2 == "b":
                    flag_new_password1 = False
                    continue
                if new_password2 != new_password1:
                    print("[ERROR] Passwords do not match.")
                    continue
                flag_new_password2 = True
        try:
            encrypted_aes_key, recovery_key = CryptoManager.encrypt_with_aes(new_password1)
            hashed_new_password = CryptoManager.hash_password(new_password1)
            response = requests.post(f"{SERVER_URL}/reset_password", json={
                "username": username, 
                "new_password": hashed_new_password,
                "new_aes": encrypted_aes_key
            })
            if response.status_code == 200:
                print(f"[STATUS] Password for '{username}' reset successfully.")
            else:
                print("[ERROR] Server error.")
                return False, None
        except requests.exceptions.RequestException as error:
            print(f"[ERROR] Network error: {error}.")
            return False, None
        return True, recovery_key
    @staticmethod
    def upload_file_IO(username, password):
        file_path_flag = False
        file_id = None
        file_path = None
        user_aes_key = None
        while not file_path_flag:
            file_path = input("Please input the path of the file to be uploaded (or type \"q\" to EXIT):\n> ")
            if file_path == 'q':
                return False
            if not os.path.isfile(file_path):
                print("[ERROR] Invalid file path or file does not exist.")
                continue
            file_path_flag = True
        file_name = os.path.basename(file_path)
        encrypted_file_path = os.path.join("temp", file_name)
        try:
            response = requests.post(f"{SERVER_URL}/get_aes", json={"username": username})
            if response.status_code == 200:
                user_aes_key = response.json()['aes']
                print(f"[STATUS] AES for '{username}' fetched successfully.")
            elif response.status_code == 400:
                error = response.json()["error"]
                print(f"[ERROR] {error}")
                return False
            else:
                print("[ERROR] Server error.")
                return False
        except requests.exceptions.RequestException as error:
            print(f"[ERROR] Network error: {error}.")
            return False
        # Process original file and make a temp new file, store the path of new into encrypted_file_path
        encrypted_file_data = CryptoManager.encrypt_file_with_aes(password, user_aes_key, file_path)
        files = {'file': encrypted_file_data}
        try:
            response = requests.post(f"{SERVER_URL}/upload_file", files=files, data={'username': username})
            if response.status_code == 200:
                file_id = response.json()
                os.remove(encrypted_file_path)
                print(f"[STATUS] File '{username}' uploaded successfully.")
            elif response.status_code == 400:
                error = response.json()["error"]
                print(f"[ERROR] {error}")
                return False
            else:
                print("[ERROR] Server error.")
                return False
        except requests.exceptions.RequestException as error:
            print(f"[ERROR] Network error: {error}.")
            return False
        return True, file_id
    @staticmethod
    def edit_file_IO(username, password):
        """
        Update the target file by sending new content to server
        """
        # file flag tests if user has already input a target file, and path flag tests if user finish process
        file_id_flag = False
        file_path_flag = False
        file_id = None
        file_path = None
        user_aes_key = None
        while not (file_path_flag and file_id_flag):
            # Query user for the file id of file to be edited
            if not file_id_flag:
                file_id = input("Please input the file ID for the file to be edited (or type \"q\" to EXIT):\n> ")
                if file_id == "q":
                    return False
                if not Utils.check_file_id_regex(file_id):
                    print('[ERROR] Invalid file ID format.')
                    continue
                # Check if file ID exists
                file_id_flag = True
            if not file_path_flag:
                file_path = input("Please input the path of the file to be edited (or type \"q\" to EXIT, \"b\" to BACK):\n> ")
                if file_path == "q":
                    return False
                if file_path == "b":
                    file_id_flag = False
                    continue
                if not os.path.isfile(file_path):
                    print("[ERROR] Invalid file path or file does not exist.")
                    continue
                file_path_flag = True
        file_name = os.path.basename(file_path)
        encrypted_file_path = os.path.join("temp", file_name)
        try:
            response = requests.post(f"{SERVER_URL}/get_aes", json={'username': username})
            if response.status_code == 200:
                user_aes_key = response.json()['aes']
                print(f"[STATUS] AES for '{username}' fetched successfully.")
            elif response.status_code == 400:
                error = response.json()["error"]
                print(f"[ERROR] {error}")
                return False
            else:
                print("[ERROR] Server error.")
                return False
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Network error: {e}.")
            return False        
        # Process original file and make a temp new file, store the path of new into encrypted_file_path
        new_content = CryptoManager.encrypt_file_with_aes(password, user_aes_key, file_path)
        # Request for the file content from server
        data = {'username': username, 'file_id': file_id, 'content': new_content}
        try:
            response = requests.post(f"{SERVER_URL}/edit_file", json=data)
            if response.status_code == 200:
                os.remove(encrypted_file_path)
                print(f"[STATUS] File '{file_id}' uploaded successfully.")
            elif response.status_code == 403:
                error = response.json()["error"]
                print(f"[ERROR] {error}")
                return False
            else:
                print("[ERROR] Server error.")
                return False
        except requests.exceptions.RequestException as error:
            print(f"[ERROR] Network error: {error}.")
            return False
        return True
    @staticmethod
    def delete_file_IO(username):
        """
        Delete the target file from server storage
        """
        file_id_flag = False
        file_id = None
        while not (file_id_flag):
            file_id = input("Please input the file ID for the file to be deleted (or type \"q\" to EXIT):\n> ")
            if file_id == "q":
                return False
            if not Utils.check_file_id_regex(file_id):
                print('[ERROR] Invalid file ID format.')
                continue
            file_id_flag = True
        data = {'username': username, 'file_id': file_id}
        try:
            response = requests.post(f"{SERVER_URL}/delete_file", json=data)
            if response.status_code == 200:
                print(f"[STATUS] File '{file_id}' deleted successfully.")
            elif response.status_code == 403:
                error = response.json()["error"]
                print(f"[ERROR] {error}")
                return False 
            else:
                print("[ERROR] Server error.")
                return False       
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Network error: {e}.")
            return False
        return True
    @staticmethod
    def share_file_IO(username):
        """
        Fetch all users available and allow current user to choose those to share with
        Then send information to server
        """
        file_id_flag = False
        selected_usernames_id_flag = False
        file_id = None
        selected_usernames_id = None
        selected_usernames = []
        available_usernames = []
        try:
            response = requests.post(f"{SERVER_URL}/get_users")
            if response.status_code == 200:
                message = response.json()["message"]
                available_usernames = message.split(',').sort()
                available_usernames.remove(username)
            elif response.status_code == 403:
                error = response.json()["error"]
                print(f"[ERROR] {error}")
                return False
            else:
                print("[ERROR] Server error.")
                return False  
        except requests.exceptions.RequestException as error:
            print(f"[ERROR] Network error: {error}.")
            return False
        while not (file_id_flag and selected_usernames_id_flag):
            if not file_id_flag:
                file_id = input("Please input the file ID for the file to be shared (or type \"q\" to EXIT):\n> ")
                if file_id == "q":
                    return False
                if not Utils.check_file_id_regex(file_id):
                    print('[ERROR] Invalid file ID format.')
                    continue
                file_id_flag = True
            if not selected_usernames_id_flag:
                if len(available_usernames) < 1:
                    selected_usernames_id_flag = True
                    continue
                print("Added users:")
                for i in range(len(selected_usernames)):
                    print(f"{i + 1}. {selected_usernames[i]}")
                print("Other available users:")
                for i in range(len(available_usernames)):
                    print(f"{i + 1}. {available_usernames[i]}")
                selected_usernames_id = input("Please input the index of the user to share with (or type \"q\" to EXIT, \"b\" to BACK):\n> ")            
                # use \"-\" with the index (e.g. -1) to remove (to be implemented)
                if selected_usernames_id == "q":
                    return False
                if selected_usernames_id == "b":
                    available_usernames.append(selected_usernames)
                    selected_usernames = []
                    selected_usernames_id_flag = False
                    continue
                if selected_usernames_id == "c":
                    selected_usernames_id_flag = True
                    continue
                if not selected_usernames_id.isdigit():
                    print("[ERROR] Input must be a digit.")
                    continue
                if int(selected_usernames_id) > len(selected_usernames) or int(selected_usernames_id) < 1:
                    print("[ERROR] Index selected is out of range.")
                    continue
                selected_usernames.append(available_usernames.pop(int(selected_usernames_id) - 1))
        data = {"username": username, "file_id": file_id, "share_info": {}}
        try:
            response = requests.post(f"{SERVER_URL}/share_file", json={'username': username, 'file_id': file_id})
            response_data = response.json()
            if response.status_code == 200:
                shared_file_ids = response_data["shared_file_ids"]
            elif response.status_code == 403:
                error = response_data["error"]
                print(f"[ERROR] {error}")
                return None
            else: 
                print("[ERROR] Server error.")
                return False 
            # if response_data['access'] == 'shared':
            #     print("[ERROR] File shared from others can not be shared again.")      
            ##############################################################
            # Server return the encrypted file, and all pk for the users #
            ##############################################################
            for user in available_usernames:
                response = requests.post(f"{SERVER_URL}/get_rsa", json={'username': user})
                user_rsa = response.json()['rsa']
                data['share_info'][user] = CryptoManager.encrypt_file_for_sharing(user_rsa, response_data['content'])
            response = requests.post(f"{SERVER_URL}/share", json=data)
            #return response.json()
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Network error: {e}.")
            return False
        return True
    @staticmethod
    def download_file_IO(username, password):
        """
        Download an existing file from the server to a specific directory.
        """
        # Query user for the target file id
        file_id_flag = False
        file_path_flag = False
        secret_key_flag = False
        file_id = None
        file_path = None
        secret_key = None
        response_data = None
        while not (file_id_flag and file_path_flag and secret_key_flag):
            if not (file_id_flag):
                file_id = input("Please input the file ID for the file to be downloaded (or type \"q\" to EXIT):\n> ")
                if file_id == "q":
                    return None
                if not Utils.check_file_id_regex(file_id):
                    print('[ERROR] Invalid file ID format.')
                    continue
                file_id_flag = True
            if not (file_path_flag):
                file_path = input("Please input the path of the file to be edited (or type \"q\" to EXIT, \"b\" to BACK):\n> ")
                if file_path == "q":
                    return None
                if file_path == "b":
                    file_id_flag = False
                    continue
                if not os.path.isfile(file_path):
                    print("[ERROR] Invalid file path or file does not exist.")
                    continue
                # Request for the file content from server
                data = {'username': username, 'file_id': file_id}
                try:
                    response = requests.post(f"{SERVER_URL}/get_file", json=data)
                    if response.status_code == 200:
                        response_data = response.json()
                        print(f"[STATUS] File '{file_id}' fetched successfully.")
                    elif response.status_code == 403:
                        error = response.json()["error"]
                        print(f"[ERROR] {error}")
                        return False
                    else:
                        print("[ERROR] Server error.")
                        return False
                except requests.exceptions.RequestException as e:
                    print(f"[ERROR] Network error: {e}.")
                    return None
                file_path_flag = True
            if not secret_key_flag:
                if response_data['access'] == 'shared':
                    secret_key = input("Please enter your secret key to decrypt, as the file is shared (or type \"q\" to EXIT, \"b\" to BACK):\n> ")
                    if secret_key == "q":
                        return False
                    elif secret_key == "b":
                        secret_key_flag = False
                        continue
                    CryptoManager.decrypt_shared_file(secret_key, response_data['content'], file_path)
                else:
                    response = requests.post(f"{SERVER_URL}/get_aes", json={'username': username})
                    if response.status_code == 200:
                        print(f"[STATUS] AES for '{username}' fetched successfully.")
                    elif response.status_code == 400:
                        error = response.json()["error"]
                        print(f"[ERROR] {error}")
                        return False
                    else:
                        print("[ERROR] Server error.")
                        return False
                    CryptoManager.decrypt_file_with_aes(password, response.json()['aes'], response_data['content'], file_path)
                secret_key_flag = True
        #return response.json()
        return True

    def view_file_IO(self, username):
        """
        Fetch all file names in the storages that this client can read.
        """
        try:
            response = requests.post(f"{SERVER_URL}/get_files", json={"username": username})
            if response.status_code == 200:
                files = response.json()['files']
                for i in range(len(files)):
                    print(f"{i + 1}. {files[i]}")
            elif response.status_code == 403:
                error = response.json()["error"]
                print(f"[ERROR] {error}")
                return False
            else:
                print("[ERROR] Server error.")
                return False
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Network error: {e}.")
