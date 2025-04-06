import requests
import os
from SourceCode.Shared.Utils import Utils
from SourceCode.Client.CryptoManager import CryptoManager
from SourceCode.Client.RequestManager import RequestManager

SERVER_PORT = 5100
SERVER_URL = os.getenv("SERVER_URL", f"http://localhost:{SERVER_PORT}")
class ClientIO:
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
        hashed_password = None 
        while not (flag_username and flag_password1 and flag_password2):
            if not flag_username:
                username = input('Enter your email address (or type "q" to EXIT):\n> ').strip()
                if username == "q":
                    return False, None, None
                if not Utils.check_username_regex(username):
                    print('[ERROR] Invalid email format.')
                    continue
                # ==== New feature, wrap post_request into a static function
                flag_continue, flag_success, _ = RequestManager.post_request(
                    endpoint="check_username",
                    success_codes=[201],
                    retry_codes=[200]
                )
                if flag_continue: 
                    continue
                elif not flag_success:
                    return False, None, None                
                # ==== New feature, wrap post_request into a static function
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
        encrypted_aes_key, recovery_key = CryptoManager.encrypt_with_aes(password1)
        secret_key, public_key = CryptoManager.generate_rsa_key_pair()
        hashed_password = CryptoManager.hash_password(password1)
        # ==== New feature, wrap post_request into a static function
        flag_continue, flag_success, _ = RequestManager.post_request(
            endpoint="register_user",
            data={
                "username": username, 
                "password": hashed_password, 
                "encrypted_aes_key": encrypted_aes_key, 
                "public_key": public_key
            },
            success_codes=[200]
        )
        if flag_continue or not flag_success:
            return False, None, None
        # ==== New feature, wrap post_request into a static function
        return True, recovery_key, secret_key
    @staticmethod
    def login_user_IO():
        flag_username = False
        flag_password = False
        username = None
        password = None
        hashed_password = None
        while not (flag_username and flag_password):
            if not flag_username:
                username = input('Enter your email address (or type "q" to EXIT):\n> ').strip()
                if username == "q":
                    return False, None, None
                if not Utils.check_username_regex(username):
                    print('[ERROR] Invalid email format.')
                    continue
                # ==== New feature, wrap post_request into a static function
                flag_continue, flag_success, _ = RequestManager.post_request(
                    endpoint="check_username",
                    data={"username": username},
                    success_codes=[200],
                    retry_codes=[201]
                )
                if flag_continue:
                    continue
                elif not flag_success:
                    return False, None, None
                # ==== New feature, wrap post_request into a static function
                flag_username = True
            if not flag_password:
                password = input('Enter your password (or type "q" to EXIT, "b" to BACK):\n> ').strip()
                if password == "q":
                    return False, None, None
                if password == "b":
                    flag_username = False
                    continue
                if not Utils.check_password_regex(password):
                    print("[ERROR] Password must be at least 8 characters long.")
                    continue
                hashed_password = CryptoManager.hash_password(password)
                # ==== New feature, wrap post_request into a static function
                flag_continue, flag_success, _ = RequestManager.post_request(
                    endpoint="login_user",
                    data={"username": username, "password": hashed_password},
                    success_codes=[200],
                    retry_codes=[201]
                )
                if flag_continue:
                    continue
                elif not flag_success:
                    return False, None, None
                # ==== New feature, wrap post_request into a static function
                flag_password = True
        return True, username, password
    @staticmethod
    def reset_password_IO():
        flag_username = False
        flag_aes_key = False
        flag_recovery_key = False
        flag_new_password1 = False
        flag_new_password2 = False
        username = None
        aes_key = None
        recovery_key = None
        new_password1 = None
        new_password2 = None
        encrypted_aes_key = None
        recovery_key = None
        hashed_new_password = None
        while not (flag_username and flag_aes_key and flag_recovery_key and flag_new_password1 and flag_new_password2):
            if not flag_username:
                username = input('Enter your email address (or type "q" to EXIT):\n> ').strip()
                if username == "q":
                    return False, None
                if not Utils.check_username_regex(username):
                    print('[ERROR] Invalid email format.')
                    continue
                # ==== New feature, wrap post_request into a static function
                flag_continue, flag_success, _ = RequestManager.post_request(
                    endpoint="check_username",
                    data={"username": username},
                    success_codes=[200],
                    retry_codes=[201]
                )
                if flag_continue:
                    continue
                elif not flag_success:
                    return False, None
                # ==== New feature, wrap post_request into a static function
                flag_username = True
            if not flag_aes_key:
                # ==== New feature, wrap post_request into a static function
                flag_continue, flag_success, data = RequestManager.post_request(
                    endpoint="get_aes_key",
                    data={"username": username},
                    success_codes=[200],
                    retry_codes=[400],
                    return_data_keys=["aes_key"]
                )
                if flag_continue:
                    continue
                elif not flag_success:
                    return False, None
                aes_key = data["aes_key"]
                # ==== New feature, wrap post_request into a static function
                flag_aes_key = True
            if not flag_recovery_key:
                recovery_key = input('Enter your recovery key (or type "q" to EXIT, "b" to BACK):\n> ').strip()
                if recovery_key == "q":
                    return False, None
                if recovery_key == "b":
                    flag_username = False
                    continue
                if not CryptoManager.verify_recovery_key(recovery_key, aes_key):
                    print("[ERROR] Validation failed. Recovery key is incorrect.")
                    continue
                print("[STATUS] Validation succeed. Recovery key is correct.")
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
        encrypted_aes_key, recovery_key = CryptoManager.encrypt_with_aes(new_password1)
        hashed_new_password = CryptoManager.hash_password(new_password1)
        flag_continue, flag_success, _ = RequestManager.post_request(
            endpoint="reset_password",
            data={
                "username": username, 
                "new_password": hashed_new_password,
                "new_aes_key": encrypted_aes_key
            },
            success_codes=[200]
        )
        if flag_continue or not flag_success:
            return False, None
        return True, recovery_key
    @staticmethod
    def upload_file_IO(username, password):
        file_path_flag = False
        aes_key_flag = False
        file_path = None
        aes_key = None
        file_id = None
        encrypted_file_data = None
        files = None
        while not (file_path_flag and aes_key_flag):
            if not file_path_flag:
                file_path = input("Please input the path of the file to be uploaded (or type \"q\" to EXIT):\n> ")
                if file_path == 'q':
                    return False, None
                if not os.path.isfile(file_path):
                    print("[ERROR] Invalid file path or file does not exist.")
                    continue
                file_path_flag = True
            if not aes_key_flag:
                try:
                    response = requests.post(f"{SERVER_URL}/get_aes_key", json={
                        "username": username
                        })
                    if response.status_code == 200:
                        response_data = response.json()
                        aes_key = response_data["aes_key"]
                        print(response_data["message"])
                    elif response.status_code in [400, 401, 403]:
                        response_data = response.json()
                        print(response_data["message"])
                        return False, None
                    else:
                        print("[ERROR] Server error.")
                        return False, None
                except requests.exceptions.RequestException as error:
                    print(f"[ERROR] Network error: {error}.")
                    return False, None
                aes_key_flag = True
        encrypted_file_data = CryptoManager.encrypt_file_with_aes(password, aes_key, file_path) 
        files = {'file': encrypted_file_data} # files = {'file': (os.path.basename(file_path), encrypted_file_data)}
        try:
            response = requests.post(f"{SERVER_URL}/upload_file", 
                                     files=files, 
                                     data={'username': username})
            data = response.json
            if response.status_code == 200:
                file_id = data["file_id"]
                print(data["message"])
            elif response.status_code in [400, 403]:
                print(data["message"])
                return False, None
            else:
                print("[ERROR] Server error.")
                return False, None
        except requests.exceptions.RequestException as error:
            print(f"[ERROR] Network error: {error}.")
            return False, None
        return True, file_id
    @staticmethod
    def edit_file_IO(username, password):
        files_flag = False
        file_id_flag = False
        file_path_flag = False
        files = None
        file_id = None
        file_path = None
        aes_key = None
        while not (files_flag and file_path_flag and file_id_flag):
            if not files_flag:
                try:
                    response = requests.post(f"{SERVER_URL}/get_files", json={
                        "username": username
                        })
                    if response.status_code == 200:
                        response_data = response.json()
                        files = response_data["files"]
                        print(response_data["message"])
                    elif response.status_code in [400, 403]:
                        response_data = response.json()
                        print(response_data["message"])
                        return False
                    else:
                        print("[ERROR] Server error.")
                        return False
                except requests.exceptions.RequestException as error:
                    print(f"[ERROR] Network error: {error}.")
                    return False  
                files_flag = True      
            if not file_id_flag:
                print("[FILES] List of files:")
                for file in files:
                    print(f"- File ID: {file['file_id']}, File Name: {file['file_name']}, Access: {file['access']}")
                file_id = input("Please input the file ID for the file to be edited (or type \"q\" to EXIT):\n> ")
                if file_id == "q":
                    return False
                if not Utils.check_file_id_regex(file_id):
                    print('[ERROR] Invalid file ID format.')
                    continue
                try:
                    response = requests.post(f"{SERVER_URL}/check_file_id", json={
                        "username": username, 
                        "file_id": file_id
                        })
                    if response.status_code == 200:
                        response_data = response.json()
                        print(response_data["message"])
                    elif response.status_code == 201:
                        response_data = response.json()
                        print(response_data["message"])
                        continue
                    elif response.status_code in [400, 401]:
                        response_data = response.json()
                        print(response_data["message"])
                        return False
                    else:
                        print("[ERROR] Server error.")
                        return False
                except requests.exceptions.RequestException as error:
                    print(f"[ERROR] Network error: {error}.")
                    return False     
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
        try:
            response = requests.post(f"{SERVER_URL}/get_aes_key", json={'username': username})
            if response.status_code == 200:
                response_data = response.json()
                aes_key = response_data["aes_key"]
                print(response_data["message"])
            elif response.status_code == [400, 401, 403]:
                response_data = response.json()
                print(response_data["message"])
                return False
            else:
                print("[ERROR] Server error.")
                return False
        except requests.exceptions.RequestException as error:
            print(f"[ERROR] Network error: {error}.")
            return False        
        new_content = CryptoManager.encrypt_file_with_aes(password, aes_key, file_path)
        payload = {'username': username, 'file_id': file_id, 'content': new_content}
        try:
            response = requests.post(f"{SERVER_URL}/edit_file", json=payload)
            if response.status_code == 200:
                response_data = response.json()
                print(response_data["message"])
            elif response.status_code in [400, 403]:
                response_data = response.json()
                print(response_data["message"])
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
        file_id_flag = False
        file_id = None
        while not (file_id_flag):
            file_id = input("Please input the file ID for the file to be deleted (or type \"q\" to EXIT):\n> ")
            if file_id == "q":
                return False
            if not Utils.check_file_id_regex(file_id):
                print('[ERROR] Invalid file ID format.')
                continue
            try:
                response = requests.post(f"{SERVER_URL}/check_file_id", json={
                    "username": username, 
                    "file_id": file_id
                    })
                if response.status_code == 200:
                    response_data = response.json()
                    print(response_data["message"])
                elif response.status_code == 201:
                    response_data = response.json()
                    print(response_data["message"])
                    continue
                elif response.status_code in [400, 401]:
                    response_data = response.json()
                    print(response_data["message"])
                    return False
                else:
                    print("[ERROR] Server error.")
                    return False
            except requests.exceptions.RequestException as error:
                print(f"[ERROR] Network error: {error}.")
                return False
            file_id_flag = True
        payload = {'username': username, 'file_id': file_id}
        try:
            response = requests.post(f"{SERVER_URL}/delete_file", json=payload)
            if response.status_code == 200:
                response_data = response.json()
                print(response_data["message"])
            elif response.status_code in [400, 403]:
                response_data = response.json()
                print(response_data["message"])
                return False 
            else:
                print("[ERROR] Server error.")
                return False       
        except requests.exceptions.RequestException as error:
            print(f"[ERROR] Network error: {error}.")
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
                response_data = response.json()
                usernames = response_data["usernames"]
                available_usernames = usernames.split(',').sort()
                available_usernames.remove(username)
                print(response_data["message"])
            elif response.status_code == 403:
                response_data = response.json()
                print(response_data["message"])
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
                try:
                    response = requests.post(f"{SERVER_URL}/check_file_id", json={
                        "username": username, 
                        "file_id": file_id
                        })
                    if response.status_code == 200:
                        response_data = response.json()
                        print(response_data["message"])
                    elif response.status_code == 201:
                        response_data = response.json()
                        print(response_data["message"])
                        continue
                    elif response.status_code in [400, 401]:
                        response_data = response.json()
                        print(response_data["message"])
                        return False
                    else:
                        print("[ERROR] Server error.")
                        return False
                except requests.exceptions.RequestException as error:
                    print(f"[ERROR] Network error: {error}.")
                    return False
                file_id_flag = True
            if not selected_usernames_id_flag:
                if len(available_usernames) < 1 and len(selected_usernames) < 1:
                    print("[STATUS] There are no more available usernames to share with.")
                    selected_usernames_id_flag = True
                    continue
                print("\nAdded users to share with:")
                if not selected_usernames:
                    print("  (None)")
                else:
                    for i in range(len(selected_usernames)):
                        print(f"  {i + 1}. {selected_usernames[i]}")
                print("Other available users:")
                if not available_usernames:
                    print("  (None)")
                else:
                    for i in range(len(available_usernames)):
                        print(f"  {i + 1}. {available_usernames[i]}")
                selected_usernames_id = input(
                    "Please input the index of the user to share with (or type \"q\" to EXIT, \"b\" to BACK, \"c\" to CONTINUE, or \"-<index>\" to remove a user, e.g., -1):\n> "
                ).strip()
                if selected_usernames_id == "q":
                    return False
                if selected_usernames_id == "b":
                    available_usernames.extend(selected_usernames)
                    available_usernames.sort()
                    selected_usernames = []
                    continue
                if selected_usernames_id == "c":
                    if not selected_usernames:
                        print("[ERROR] You must select at least one user to share with.")
                        continue
                elif selected_usernames_id.startswith("-"):
                    if not selected_usernames:
                        print("[ERROR] No users to remove. Add users first.")
                        continue
                    try:
                        remove_index = int(selected_usernames_id[1:])
                        if remove_index < 1 or remove_index > len(selected_usernames):
                            print("[ERROR] Index to remove is out of range.")
                            continue
                        removed_user = selected_usernames.pop(remove_index - 1)
                        available_usernames.append(removed_user)
                        available_usernames.sort()
                        print(f"[STATUS] Removed {removed_user} from the share list.")
                    except ValueError:
                        print("[ERROR] Invalid removal index. Use format like '-1'.")
                    continue
                else:
                    if not selected_usernames_id.isdigit():
                        print("[ERROR] Input must be a digit (or a negative index to remove).")
                        continue
                    selected_index = int(selected_usernames_id)
                    if selected_index < 1 or selected_index > len(available_usernames):
                        print("[ERROR] Index selected is out of range.")
                        continue
                    selected_user = available_usernames.pop(selected_index - 1)
                    selected_usernames.append(selected_user)
                    print(f"[STATUS] Added {selected_user} to the share list.")
                    continue
                selected_usernames_id_flag = True
        # data = {"username": username, "file_id": file_id, "share_info": {}}
        # try:
        #     response = requests.post(f"{SERVER_URL}/share_file", json={'username': username, 'file_id': file_id})
        #     fetched_file = response.json()
        #     if response.status_code == 200:
        #         shared_file_ids = fetched_file["shared_file_ids"]
        #     elif response.status_code == 403:
        #         error = fetched_file["error"]
        #         print(f"[ERROR] {error}")
        #         return None
        #     else: 
        #         print("[ERROR] Server error.")
        #         return False 
        #     # if fetched_file['access'] == 'shared':
        #     #     print("[ERROR] File shared from others can not be shared again.")      
        #     ##############################################################
        #     # Server return the encrypted file, and all pk for the users #
        #     ##############################################################
        #     for user in available_usernames:
        #         response = requests.post(f"{SERVER_URL}/get_rsa", json={'username': user})
        #         user_rsa = response.json()['rsa']
        #         data['share_info'][user] = CryptoManager.encrypt_file_for_sharing(user_rsa, fetched_file['content'])
        #     response = requests.post(f"{SERVER_URL}/share", json=data)
        #     #return response.json()
        # except requests.exceptions.RequestException as e:
        #     print(f"[ERROR] Network error: {e}.")
        #     return False
        # return True
    @staticmethod
    def download_file_IO(username, password):
        """
        Download an existing file from the server to a specific directory.
        """
        file_id_flag = False
        file_path_flag = False
        secret_key_flag = False
        file_id = None
        file_path = None
        secret_key = None
        fetched_file = None
        while not (file_id_flag and file_path_flag and secret_key_flag):
            if not (file_id_flag):
                file_id = input("Please input the file ID for the file to be downloaded (or type \"q\" to EXIT):\n> ")
                if file_id == "q":
                    return None
                if not Utils.check_file_id_regex(file_id):
                    print('[ERROR] Invalid file ID format.')
                    continue
                try:
                    response = requests.post(f"{SERVER_URL}/check_file_id", json={
                        "username": username, 
                        "file_id": file_id
                        })
                    if response.status_code == 200:
                        response_data = response.json()
                        print(response_data["message"])
                    elif response.status_code == 201:
                        response_data = response.json()
                        print(response_data["message"])
                        continue
                    elif response.status_code in [400, 401]:
                        response_data = response.json()
                        print(response_data["message"])
                        return False
                    else:
                        print("[ERROR] Server error.")
                        return False
                except requests.exceptions.RequestException as error:
                    print(f"[ERROR] Network error: {error}.")
                    return False
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
                payload = {'username': username, 'file_id': file_id}
                try:
                    response = requests.post(f"{SERVER_URL}/view_file", json=payload)
                    if response.status_code == 200:
                        fetched_file = response.json()
                        print(f"[STATUS] File '{file_id}' fetched successfully.")
                    elif response.status_code in [400, 403]:
                        response_data = response.json()
                        print(response_data["message"])
                        return False
                    else:
                        print("[ERROR] Server error.")
                        return False
                except requests.exceptions.RequestException as error:
                    print(f"[ERROR] Network error: {error}.")
                    return None
                file_path_flag = True
            if not (secret_key_flag):
                if fetched_file['access'] == 'shared':
                    secret_key = input("Please enter your secret key to decrypt, as the file is shared (or type \"q\" to EXIT, \"b\" to BACK):\n> ")
                    if secret_key == "q":
                        return False
                    elif secret_key == "b":
                        file_path_flag = False
                        continue
                    CryptoManager.decrypt_shared_file(secret_key, fetched_file['content'], file_path)
                else:
                    response = requests.post(f"{SERVER_URL}/get_aes_key", json={'username': username})
                    if response.status_code == 200:
                        response_data = response.json()
                        print(response_data["message"])
                    elif response.status_code in [400, 401, 403]:
                        response_data = response.json()
                        print(response_data["message"])
                        return False
                    else:
                        print("[ERROR] Server error.")
                        return False
                    CryptoManager.decrypt_file_with_aes(password, data["aes_key"], fetched_file['content'], file_path)
                secret_key_flag = True
        return True
    @staticmethod
    def check_file_IO(username):
        """
        Fetch all file names in the storages that this client can read.
        """
        files = None
        try:
            response = requests.post(f"{SERVER_URL}/get_files", json={"username": username})
            if response.status_code == 200:
                fetched_files = response.json()
                files = fetched_files['files']
                print(fetched_files["message"])
                for i in range(len(files)):
                    print(f"{i + 1}. {files[i]}")
            elif response.status_code == [400, 403]:
                response_data = response.json()
                print(response_data["message"])
                return False
            else:
                print("[ERROR] Server error.")
                return False
        except requests.exceptions.RequestException as error:
            print(f"[ERROR] Network error: {error}.")
        return True
