import requests
import os
from SourceCode.shared.utils import check_username_regex, check_password_regex, generate_aes, hash_password, split_aes
from encryption import CryptoHandler

class UserManagement:
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

                    aes_key = generate_aes()
                    server_aes, client_aes = split_aes(aes_key)
                    response = requests.post(f"{self.server_url}/register", json={"username": username, "password": password1, "key": server_aes.hex()})
                    if response.status_code == 200:
                        flag_password2 = True
                        response = response.json()
                        client_aes = bytes.fromhex(client_aes.hex())  
                        print(f"[STATUS] Email '{username}' registered successfully.")
                        return client_aes
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
                    return False, None
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
                        return False, None
                except requests.exceptions.RequestException as e:
                    print(f"[ERROR] Network error: {e}.")
                    return False, None
            elif not flag_password:
                password = input('Enter your password (or type "q" to EXIT, "b" to BACK):\n> ').strip()
                if password == "q":
                    return False, None
                if password == "b":
                    flag_username = False, None
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
                        return False, None
                except requests.exceptions.RequestException as e:
                    print(f"[ERROR] Network error: {e}.")
                    return False, None
        return True, username

    def reset_password_IO(self):
        flag_username, flag_old_password, flag_new_password1, flag_new_password2 = False, False, False, False
        username, old_password, new_password1, new_password2 = None, None, None, None
        while not (flag_username and flag_old_password and flag_new_password1 and flag_new_password2):
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
                        print("[ERROR] Server error")
                        return False
                except requests.exceptions.RequestException as e:
                    print(f"[ERROR] Network error: {e}")
                    return False
            elif not flag_old_password:
                old_password = input('Enter your old password (or type "q" to EXIT, "b" to BACK):\n> ').strip()
                if old_password == "q":
                    return False
                if old_password == "b":
                    flag_username = False
                    continue
                try:
                    response = requests.post(f"{self.server_url}/login", json={"username": username, "password": old_password})
                    if response.status_code == 200:
                        flag_old_password = True
                    elif response.status_code == 201:
                        print("[ERROR] Incorrect password.")
                    else:
                        print("[ERROR] Server error")
                        return False
                except requests.exceptions.RequestException as e:
                    print(f"[ERROR] Network error: {e}")     
                    return False           
            elif not flag_new_password1:
                new_password1 = input('Enter a new password with at least 8 characters (or type "q" to EXIT, "b" to BACK):\n> ').strip()
                if new_password1 == "q":
                    return False
                if new_password1 == "b":
                    flag_old_password = False
                    continue
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
                    response = requests.post(f"{self.server_url}/reset_password", json={
                        "username": username,
                        "new_password": new_password1
                    })
                    if response.status_code == 200:
                        flag_new_password2 = True
                        print(f"[STATUS] Password for '{username}' has been successfully reset.")
                    else:
                        print("[ERROR] Server error")
                        return False
                except requests.exceptions.RequestException as e:
                    print(f"[ERROR] Network error: {e}")
                    return False
        return True
    
    def user_read_storage(self, username):
        """
        Fetch all file names in the storages that this client can read.
        """
        try:
            response = requests.post(f"{self.server_url}/view_files", json={"username": username})

            #Print out existing files with id
            if response.status_code == 200:
                print(response.json()["files"])
            else:
                print("[ERROR] Server error.")
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Network error: {e}.")
        return
    
    def upload_file(self, username):
        """
        Encrypt and upload a file to the server
        """
        file_path = input("Please input the path of the file to be uploaded (or type \"q\" to EXIT):\n> ")
        if file_path == 'q':
            return None
        
        if os.path.isfile(file_path):
            # Encrypt the target file and store cipher text into temp file
            encrypter = CryptoHandler()
            encry_file_path = None
            #### user encrypter to process original file and make a temp new file, store the path of new into encry_file_path

            # Open the temp file and send to server
            with open(encry_file_path, 'rb') as file:
                files = {'file': file}
                data = {'username': username}
            try:
                    response = requests.post(f"{self.server_url}/upload", files=files, data=data)
                    if response.status_code == 400:
                        print(f"[ERROR] {response.json()["error"]}")
                        return None
                    return response.json()
            except requests.exceptions.RequestException as e:
                print(f"[ERROR] Network error: {e}.")
                return None
        print("[ERROR] Invalid file path or file does not exist.")

    def download_file(self, username):
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
                print("[ERROR] Please input an valid integer")
            except requests.exceptions.RequestException as e:
                print(f"[ERROR] Network error: {e}.")
                return None
            
    def edit_file(self, username):
        """
        Update the target file by sending new content to server
        """
        # input flag tests if user has already input a target file, and path flag tests if user finish process
        path_flag = False
        input_flag = False
        file_id = 0
        while not path_flag:
            try:
                # Query user for the file id of file to be edited
                if not input_flag:
                    choice = input("Please input the file ID for the file to be edited (or type \"q\" to EXIT):\n> ")
                    if choice == 'q':
                        return None
                    file_id = int(choice)
                input_flag = True

                # Query user for local file to replace
                choice = input("Please input the path of the file to be edited  (or type \"q\" to EXIT, \"b\" to BACK):\n> :\n> ")
                if choice == "q":
                    return None
                # Re-enter target file
                if choice == "b":
                    input_flag = False
                    continue
                file_path = choice
                if os.path.isfile(file_path):
                    # Encrypt the target file and store cipher text into temp file
                    encrypter = CryptoHandler()
                    encry_file_path = None
                    #### use encrypter to process original file and make a temp new file, store the path of new into encry_file_path

                    # Open the temp file and send to server
                    with open(encry_file_path, 'rb') as file:
                        new_content = {'file': file}

                    # Request for the file content from server
                    data = {'username': username, 'file_id': file_id, 'content': new_content}
                    response = requests.post(f"{self.server_url}/edit", json=data)
                    if response.status_code == 403:
                            print(f"[ERROR] {response.json()["error"]}")
                            return None
                    return response.json()
                print("[ERROR] Invalid file path or file does not exist.")
            
            except ValueError:
                print("[ERROR] Please input an valid integer")
            except requests.exceptions.RequestException as e:
                print(f"[ERROR] Network error: {e}.")
                return None

    def share_users(self, username):
        pass
        



    
    '''
Request Examples of File Manager

import requests

SERVER_URL = "http://localhost:5000"

def upload_file(username, file_path):
    with open(file_path, 'rb') as file:
        files = {'file': file}
        data = {'username': username}
        response = requests.post(f"{SERVER_URL}/upload", files=files, data=data)
    return response.json()

def edit_file(username, file_id, new_content):
    data = {'username': username, 'file_id': file_id, 'content': new_content}
    response = requests.post(f"{SERVER_URL}/edit", json=data)
    return response.json()

def delete_file(username, file_id):
    data = {'username': username, 'file_id': file_id}
    response = requests.post(f"{SERVER_URL}/delete", json=data)
    return response.json()

def share_file(username, file_id, users):
    data = {'username': username, 'file_id': file_id, 'users': users}
    response = requests.post(f"{SERVER_URL}/share", json=data)
    return response.json()

def get_file(username, file_id):
    data = {'username': username, 'file_id': file_id}
    response = requests.post(f"{SERVER_URL}/get", json=data)
    return response.json()




if __name__ == "__main__":
    username = "alice"
    file_path = "example.txt"
    
    # Upload a file
    upload_response = upload_file(username, file_path)
    print("Upload Response:", upload_response)
    
    if "file_id" in upload_response:
        file_id = upload_response["file_id"]
        
    # Edit the file
    edit_response = edit_file(username, file_id, "Updated content")
    print("Edit Response:", edit_response)
    
    # Share the file
    share_response = share_file(username, file_id, ["bob"])
    print("Share Response:", share_response)
    
    # Get the file (as Bob)
    get_response = get_file("bob", file_id)
    print("Get Response (Bob):", get_response)
    
    # Delete the file
    delete_response = delete_file(username, file_id)
    print("Delete Response:", delete_response)
'''