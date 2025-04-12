import requests
import time
import os
from SourceCode.Shared.Utils import Utils
from SourceCode.Client.CryptoManager import CryptoManager

SERVER_URL = os.getenv("SERVER_URL", "http://localhost:5100")
class ClientIO:
    @staticmethod
    def register_user_IO():
        """
        Registers a new user by collecting their email and password,
        sending a one-time password (OTP) for verification, and handling
        all necessary encryption and server communication.

        Returns:
        tuple: (bool, recovery_key, secret_key) 
            - bool: Indicates success (True) or failure (False) of registration.
            - recovery_key: The recovery key generated for the user.
            - secret_key: The secret key generated for the user.
        """
        
        # Flags to track the registration process
        flag_username = False
        flag_password1 = False
        flag_password2 = False
        flag_send_otp = False
        flag_otp = False
        # Variables to store user information
        username = None
        password1 = None
        password2 = None
        encrypted_aes_key = None
        recovery_key = None
        secret_key = None
        public_key = None       
        hashed_password = None 
        # Main loop to gather user input and ensure all registration steps are completed
        while not (flag_username and flag_password1 and flag_password2 and flag_send_otp and flag_otp):
            # Check for valid username input
            if not flag_username:
                username = input('Enter your email address (or type "q" to EXIT):\n> ').strip()
                if username == "q":
                    return False, None, None
                # Validate username format
                if not Utils.check_username_regex(username):
                    print('[ERROR] Invalid email format.')
                    continue
                # Verify if the username is available on the server
                try:
                    response = requests.get(f"{SERVER_URL}/check_username", json={"username": username})
                    # Handle the response based on status code
                    if response.status_code == 201:
                        response_data = response.json()
                        print(response_data["message"])
                    elif response.status_code in [200, 400]:
                        response_data = response.json()
                        print(response_data["message"])
                        continue
                    elif response.status_code == 403:
                        response_data = response.json()
                        print(response_data["message"])
                        return False, None, None
                    else:
                        print("[ERROR] Server error.")
                        return False, None, None
                except requests.exceptions.RequestException as error:
                    print(f"[ERROR] Network error: {error}.")
                    continue
                flag_username = True
            # Check for valid password input
            if not flag_password1:
                password1 = input('Enter a password with at least 8 characters (or type "q" to EXIT, "b" to BACK):\n> ').strip()
                if password1 == "q":
                    return False, None, None
                if password1 == "b":
                    flag_username = False
                    continue
                # Validate password format
                if not Utils.check_password_regex(password1):
                    print("[ERROR] Password must be at least 8 characters long.")
                    continue
                flag_password1 = True
            # Confirm password input
            if not flag_password2:
                password2 = input('Confirm your password (or type "q" to EXIT, "b" to BACK):\n> ').strip()
                if password2 == "q":
                    return False, None, None
                if password2 == "b":
                    flag_password1 = False
                    continue
                # Verify that both passwords match
                if password2 != password1:
                    print("[ERROR] Passwords do not match.")
                    continue
                # Encrypt keys and send registration email
                encrypted_aes_key, recovery_key = CryptoManager.encrypt_with_aes(password1)
                secret_key, public_key = CryptoManager.generate_rsa_key_pair()
                # send secret key and recovery key as attachments to user email 
                Utils.send_registration_email(username, secret_key, recovery_key)
                hashed_password = CryptoManager.hash_password(password1)
                flag_password2 = True
            # Request to send OTP for verification
            if not flag_send_otp:
                try:
                    # Send a GET request to generate and send the OTP to the user's email
                    response = requests.get(f"{SERVER_URL}/get_registration_otp", data={
                        "username": username, 
                        "password": hashed_password, 
                        "public_key": public_key
                        }, files = {'encrypted_aes_key': encrypted_aes_key})
                    # Handle server response for OTP request 
                    if response.status_code == 200:
                        response_data = response.json()
                        print(response_data["message"])
                    elif response.status_code == 400:
                        response_data = response.json()
                        print(response_data["message"])
                        flag_username = False
                        flag_password1 = False
                        flag_password2 = False
                        continue
                    elif response.status_code == 403:
                        response_data = response.json()
                        print(response_data["message"])
                        return False, None, None
                    else:
                        print("[ERROR] Server error.")
                        return False, None, None
                except requests.exceptions.RequestException as error:
                    print(f"[ERROR] Network error: {error}.")
                    return False, None, None
                flag_send_otp = True
            # Verify the OTP entered by the user
            if not flag_otp:
                otp = input('Enter the OTP sent to your email (or type "q" to EXIT, "b" to BACK):\n> ').strip()
                if otp == 'q':
                    return False, None, None
                if otp == 'b':
                    flag_password1 = False
                    flag_password2 = False
                    flag_send_otp = False
                    continue
                try:
                    # Send a POST request to verify the OTP entered by the user
                    response = requests.post(f"{SERVER_URL}/verify_registration_otp", json={"username": username, "otp": otp})
                    # Handle server response for OTP verification
                    if response.status_code == 200:
                        response_data = response.json()
                        print(response_data["message"])
                    elif response.status_code == 201:
                        response_data = response.json()
                        print(response_data["message"])
                        continue
                    elif response.status_code == 202:
                        response_data = response.json()
                        print(response_data["message"])
                        flag_send_otp = False
                        continue
                    elif response.status_code == 400:
                        response_data = response.json()
                        print(response_data["message"])
                        flag_username = False
                        flag_password1 = False
                        flag_password2 = False
                        flag_send_otp = False
                        continue
                    elif response.status_code == 403:
                        response_data = response.json()
                        print(response_data["message"])
                        return False, None, None
                    else:
                        print("[ERROR] Server error.")
                        return False, None, None
                except requests.exceptions.RequestException as error:
                    print(f"[ERROR] Network error: {error}.")
                    return False, None, None
                flag_otp = True
        return True, recovery_key, secret_key   # Return success and generated keys
    @staticmethod
    def login_user_IO():
        """
        Handles the user login process by collecting the username and password,
        verifying the credentials, and sending a one-time password (OTP) for 
        additional security.

        Returns:
        tuple: (bool, username, password) 
            - bool: Indicates success (True) or failure (False) of login.
            - username: The email address of the user attempting to log in.
            - password: The password entered by the user.
        """
        
        # Flags to track the login process
        flag_username = False
        flag_get_password = False
        flag_password = False
        flag_send_otp = False
        flag_otp = False
        
        # Variables to store user information
        username = None
        hashed_password = None
        password = None
        otp = None
        
        # Main loop to gather user input and ensure all login steps are completed
        while not (flag_username and flag_get_password and flag_password and flag_send_otp and flag_otp):
            
            # Check for valid username input
            if not flag_username:
                username = input('Enter your email address (or type "q" to EXIT):\n> ').strip()
                if username == "q":
                    return False, None, None
                
                # Validate username format
                if not Utils.check_username_regex(username):
                    print('[ERROR] Invalid email format.')
                    continue
                
                try:
                    # Send a GET request to check if the username exists
                    response = requests.get(f"{SERVER_URL}/check_username", json={
                        "username": username
                    })
                    
                    # Handle the response based on status code
                    if response.status_code == 200:
                        response_data = response.json()
                        print(response_data["message"])
                    elif response.status_code in [201, 400]:
                        response_data = response.json()
                        print(response_data["message"])
                        continue
                    elif response.status_code == 403:
                        response_data = response.json()
                        print(response_data["message"])
                        return False, None, None
                    else:
                        print("[ERROR] Server error.")
                        return False, None, None
                except requests.exceptions.RequestException as error:
                    print(f"[ERROR] Network error: {error}.")
                    return False, None, None
                
                flag_username = True  # Mark username step as completed

            # Attempt to retrieve the hashed password for the given username
            if not flag_get_password:
                try:
                    # Send a GET request to fetch the hashed password
                    response = requests.get(f"{SERVER_URL}/get_password", json={"username": username})
                    
                    # Handle the response for password retrieval
                    if response.status_code == 200:
                        response_data = response.json()
                        print(response_data["message"])
                        hashed_password = response_data["hashed_password"]
                    elif response.status_code == 400:
                        response_data = response.json()
                        print(response_data["message"])
                        flag_username = False
                        continue
                    elif response.status_code in [201, 403]:
                        response_data = response.json()
                        print(response_data["message"])
                        return False, None, None
                    else:
                        print("[ERROR] Server error.")
                        return False, None, None
                except requests.exceptions.RequestException as error:
                    print(f"[ERROR] Network error: {error}.")
                    return False, None, None
                
                flag_get_password = True  # Mark password retrieval as completed

            # Check for valid user password input
            if not flag_password:
                password = input('Enter your password (or type "q" to EXIT, "b" to BACK):\n> ').strip()
                if password == "q":
                    return False, None, None
                if password == "b":
                    flag_username = False
                    flag_get_password = False
                    continue
                
                # Validate password length
                if not Utils.check_password_regex(password):
                    print("[ERROR] Password must be at least 8 characters long.")
                    continue
                
                # Verify the entered password against the hashed password
                if not CryptoManager.check_password(password, hashed_password):
                    print(f"[ERROR] Email '{username}' failed to log in. Please double check your password.")
                    continue
                
                print(f"[STATUS] Email '{username}''s password is correct.")
                flag_password = True  # Mark password entry as completed

            # Request to send OTP for additional verification
            if not flag_send_otp:
                try:
                    # Send a GET request to generate and send the OTP to the user's email
                    response = requests.get(f"{SERVER_URL}/get_login_otp", json={"username": username})
                    
                    # Handle server response for OTP request
                    if response.status_code == 200:
                        response_data = response.json()
                        print(response_data["message"])
                    elif response.status_code == 400:
                        response_data = response.json()
                        print(response_data["message"])
                        flag_username = False
                        flag_get_password = False
                        flag_password = False
                        continue
                    elif response.status_code == 403:
                        response_data = response.json()
                        print(response_data["message"])
                        return False, None, None
                    else:
                        print(response.json()["message"])
                        return False, None, None
                except requests.exceptions.RequestException as error:
                    print(f"[ERROR] Network error: {error}.")
                    return False, None, None
                
                flag_send_otp = True  # Mark OTP sending as completed

            # Verify the OTP entered by the user
            if not flag_otp:
                otp = input('Enter the OTP sent to your email (or type "q" to EXIT, "b" to BACK):\n> ').strip()
                if otp == 'q':
                    return False, None, None
                if otp == 'b':
                    flag_password = False
                    flag_send_otp = False
                    continue
                
                try:
                    # Send a POST request to verify the OTP
                    response = requests.post(f"{SERVER_URL}/verify_login_otp", json={"username": username, "otp": otp})
                    
                    # Handle server response for OTP verification
                    if response.status_code == 200:
                        response_data = response.json()
                        print(response_data["message"])
                    elif response.status_code == 201:
                        response_data = response.json()
                        print(response_data["message"])
                        continue
                    elif response.status_code == 202:
                        response_data = response.json()
                        print(response_data["message"])
                        flag_send_otp = False
                        continue
                    elif response.status_code == 400:
                        response_data = response.json()
                        print(response_data["message"])
                        flag_username = False
                        flag_get_password = False
                        flag_password = False
                        flag_send_otp = False
                        continue
                    elif response.status_code == 403:
                        response_data = response.json()
                        print(response_data["message"])
                        return False, None, None
                    else:
                        print(response_data["message"])
                        return False, None, None
                except requests.exceptions.RequestException as error:
                    print(f"[ERROR] Network error: {error}.")
                    return False, None, None
                
                flag_otp = True  # Mark OTP verification as completed

        return True, username, password  # Return success and user credentials
    @staticmethod
    def reset_password_IO():
        """
        Manages the password reset process by verifying the user's email,
        retrieving their encrypted AES key, validating the recovery key,
        and allowing the user to set a new password.

        Returns:
        tuple: (bool, recovery_key) 
            - bool: Indicates success (True) or failure (False) of the password reset.
            - recovery_key: The recovery key generated for the user upon successful reset.
        """
        
        # Flags to track the password reset process
        flag_username = False
        flag_aes_key = False
        flag_recovery_key = False
        flag_new_password1 = False
        flag_new_password2 = False
        flag_send_otp = False
        flag_otp = False
        
        # Variables to store user information
        username = None
        original_encrypted_aes_key = None
        recovery_key_path = None
        new_password1 = None
        new_password2 = None
        encrypted_aes_key = None
        hashed_new_password = None
        
        # Main loop to gather user input and ensure all reset steps are completed
        while not (flag_username and flag_aes_key and flag_recovery_key and flag_new_password1 and flag_new_password2 and flag_send_otp and flag_otp):
            
            # Check for valid username input
            if not flag_username:
                username = input('Enter your email address (or type "q" to EXIT):\n> ').strip()
                if username == "q":
                    return False, None, None
                
                # Validate username format
                if not Utils.check_username_regex(username):
                    print('[ERROR] Invalid email format.')
                    continue
                
                try:
                    # Send a GET request to check if the username exists
                    response = requests.get(f"{SERVER_URL}/check_username", json={
                        "username": username
                    })
                    
                    # Handle the response based on status code
                    if response.status_code == 200:
                        response_data = response.json()
                        print(response_data["message"])
                    elif response.status_code in [201, 400]:
                        response_data = response.json()
                        print(response_data["message"])
                        continue
                    elif response.status_code == 403:
                        response_data = response.json()
                        print(response_data["message"])
                        return False, None, None
                    else:
                        print("[ERROR] Server error.")
                        return False, None, None
                except requests.exceptions.RequestException as error:
                    print(f"[ERROR] Network error: {error}.")
                    return False, None, None
                
                flag_username = True  # Mark username step as completed

            # Retrieve the encrypted AES key for the given username
            if not flag_aes_key:
                try:
                    # Send a GET request to fetch the AES key
                    response = requests.get(f"{SERVER_URL}/get_aes_key", json={
                        "username": username
                    })
                    
                    # Handle the response for AES key retrieval
                    if response.status_code == 200:
                        original_encrypted_aes_key = response.content
                    elif response.status_code == 400:
                        response_data = response.json()
                        print(response_data["message"])
                        flag_username = False
                        continue
                    elif response.status_code in [401, 403]:
                        response_data = response.json()
                        print(response_data["message"])
                        return False, None
                    else:
                        print("[ERROR] Server error.")
                        return False, None
                except requests.exceptions.RequestException as error:
                    print(f"[ERROR] Network error: {error}")     
                    return False, None
                
                flag_aes_key = True  # Mark AES key retrieval as completed

            # Validate the recovery key input
            if not flag_recovery_key:
                recovery_key_path = input('Enter the file path of your recovery key (or type "q" to EXIT, "b" to BACK):\n> ').strip()
                if recovery_key_path == "q":
                    return False, None
                if recovery_key_path == "b":
                    flag_username = False
                    flag_aes_key = False
                    continue
                
                # Check if the recovery key file exists
                if not os.path.isfile(recovery_key_path):
                    print("[ERROR] Invalid recovery_key file path or file does not exist.")
                    continue
                
                # Validate the recovery key
                with open(recovery_key_path, 'r') as recovery_key:
                    aes_key = CryptoManager.verify_recovery_key(recovery_key.read(), original_encrypted_aes_key)
                if not aes_key:
                    print("[ERROR] Validation failed. Recovery key is incorrect.")
                    continue
                
                print("[STATUS] Validation succeed. Recovery key is correct.")
                flag_recovery_key = True  # Mark recovery key validation as completed

            # Input for new password
            if not flag_new_password1:
                new_password1 = input('Enter a new password with at least 8 characters (or type "q" to EXIT, "b" to BACK):\n> ').strip()
                if new_password1 == "q":
                    return False, None
                if new_password1 == "b":
                    flag_recovery_key = False
                    continue
                
                # Validate new password length
                if not Utils.check_password_regex(new_password1):
                    print("[ERROR] Password must be at least 8 characters long.")
                    continue
                
                flag_new_password1 = True  # Mark first new password entry as completed

            # Confirm the new password
            if not flag_new_password2:
                new_password2 = input('Confirm your new password (or type "q" to EXIT, "b" to BACK):\n> ').strip()
                if new_password2 == "q":
                    return False, None
                if new_password2 == "b":
                    flag_new_password1 = False
                    continue
                
                # Check if both new passwords match
                if new_password2 != new_password1:
                    print("[ERROR] Passwords do not match.")
                    continue
                
                # Encrypt the new AES key and generate the recovery key
                encrypted_aes_key, recovery_key = CryptoManager.encrypt_with_aes(new_password1, aes_key)
                # Send the recovery key to the user's email
                Utils.send_reset_password_email(username, recovery_key)
                hashed_new_password = CryptoManager.hash_password(new_password1) 
                flag_new_password2 = True  # Mark second new password entry as completed

            # Request to send OTP for additional verification
            if not flag_send_otp:
                try:
                    # Send a GET request to generate and send the OTP to the user's email
                    response = requests.get(f"{SERVER_URL}/get_reset_otp", json={"username": username})
                    if response.status_code == 200:
                        response_data = response.json()
                        print(response_data["message"])
                    elif response.status_code == 400:
                        response_data = response.json()
                        print(response_data["message"])
                        flag_username = False
                        flag_aes_key = False
                        flag_recovery_key = False
                        flag_new_password1 = False
                        flag_new_password2 = False
                        continue
                    elif response.status_code == 403:
                        response_data = response.json()
                        print(response_data["message"])
                        return False, None
                    else:
                        response_data = response.json()
                        print(response_data["message"])
                        return False, None
                except requests.exceptions.RequestException as error:
                    print(f"[ERROR] Network error: {error}.")
                    return False, None
                
                flag_send_otp = True  # Mark OTP sending as completed

            # Verify the OTP entered by the user
            if not flag_otp:
                otp = input('Enter the OTP sent to your email (or type "q" to EXIT, "b" to BACK):\n> ').strip()
                if otp == 'q':
                    return False, None
                if otp == 'b':
                    flag_new_password1 = False
                    flag_new_password2 = False
                    flag_send_otp = False
                    continue
                
                try:
                    # Send a POST request to verify the OTP
                    response = requests.post(f"{SERVER_URL}/verify_reset_otp", data={
                        "username": username, 
                        "otp": otp,
                        "new_password": hashed_new_password,
                    }, files={"new_aes_key": encrypted_aes_key})
                    
                    # Handle server response for OTP verification
                    if response.status_code == 200:
                        response_data = response.json()
                        print(response_data["message"])
                    elif response.status_code == 201:
                        response_data = response.json()
                        print(response_data["message"])
                        continue
                    elif response.status_code == 202:
                        response_data = response.json()
                        print(response_data["message"])
                        flag_send_otp = False
                        continue
                    elif response.status_code == 400:
                        response_data = response.json()
                        print(response_data["message"])
                        flag_username = False
                        flag_aes_key = False
                        flag_recovery_key = False
                        flag_new_password1 = False
                        flag_new_password2 = False
                        flag_send_otp = False
                        continue
                    elif response.status_code == 403:
                        response_data = response.json()
                        print(response_data["message"])
                        return False, None
                    else:
                        print(response_data["message"])
                        return False, None
                except requests.exceptions.RequestException as error:
                    print(f"[ERROR] Network error: {error}.")
                    return False, None
                
                flag_otp = True  # Mark OTP verification as completed

        return True, recovery_key  # Return success and recovery key
    
    @staticmethod
    def upload_file_IO(username, password):
        """
        Manages the file upload process by collecting the file path, 
        retrieving the AES key associated with the user, and sending 
        the encrypted file data to the server.

        Parameters:
        - username: The user's username for authentication.
        - password: The user's password used for encryption.

        Returns:
        tuple: (bool, file_id) 
            - bool: Indicates success (True) or failure (False) of the upload.
            - file_id: The ID of the uploaded file if successful, None otherwise.
        """
        
        # Flags to track the upload process
        file_path_flag = False
        aes_key_flag = False
        file_path = None
        aes_key = None
        file_id = None
        encrypted_file_data = None
        files = None
        
        # Main loop to gather user input and ensure all upload steps are completed
        while not (file_path_flag and aes_key_flag):
            
            # Input for file path
            if not file_path_flag:
                file_path = input("Please input the path of the file to be uploaded (or type \"q\" to EXIT):\n> ")
                if file_path == 'q':
                    return False, None
                
                # Validate the file path
                if not os.path.isfile(file_path):
                    print("[ERROR] Invalid file path or file does not exist.")
                    continue
                
                file_path_flag = True  # Mark file path input as completed

            # Retrieve the AES key for the given username
            if not aes_key_flag:
                try:
                    # Send a GET request to fetch the AES key
                    response = requests.get(f"{SERVER_URL}/get_aes_key", json={
                        "username": username
                    })
                    
                    # Handle the response for AES key retrieval
                    if response.status_code == 200:
                        aes_key = response.content
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
                
                aes_key_flag = True  # Mark AES key retrieval as completed

        # Encrypt the file data using the retrieved AES key
        encrypted_file_data = CryptoManager.encrypt_file_with_aes(password, aes_key, file_path)
        
        # Prepare the file data for upload
        files = {'file': (os.path.basename(file_path), encrypted_file_data.hex().encode())}
        
        try:
            # Send a POST request to upload the file
            response = requests.post(f"{SERVER_URL}/upload_file", 
                                    files=files, 
                                    data={'username': username})
            
            # Handle the server response for file upload
            data = response.json()
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
        
        return True, file_id  # Return success and the file ID


    @staticmethod
    def edit_file_IO(username, password):
        """
        Facilitates the editing of an existing file by allowing the user 
        to select a file to replace, retrieving the AES key, and uploading 
        the new file content.

        Parameters:
        - username: The user's username for authentication.
        - password: The user's password used for encryption.

        Returns:
        bool: Indicates success (True) or failure (False) of the edit operation.
        """
        
        # List all (file id, file name) to facilitate user to specify the file id(s) 
        ClientIO.check_file_IO(username)
        files_flag = False
        file_id_flag = False
        file_path_flag = False
        files = None
        file_id = None
        file_path = None
        aes_key = None
        
        # Main loop to gather user input and ensure all edit steps are completed
        while not (files_flag and file_path_flag and file_id_flag):
            
            # Retrieve the list of files associated with the user
            if not files_flag:
                try:
                    # Send a GET request to fetch the user's files
                    response = requests.get(f"{SERVER_URL}/get_files", json={
                        "username": username
                    })
                    
                    # Handle the response for files retrieval
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
                files_flag = True  # Mark files retrieval as completed
            
            # Select a file to edit
            if not file_id_flag:
                print("[FILES] List of files:")
                for file in files:
                    print(f"- File ID: {file['file_id']}, File Name: {file['file_name']}, Access: {file['access']}")
                file_id = input("Please input the file ID for the file to be edited (or type \"q\" to EXIT):\n> ")
                if file_id == "q":
                    return False
                
                # Validate the file ID format
                if not Utils.check_file_id_regex(file_id):
                    print('[ERROR] Invalid file ID format.')
                    continue
                
                try:
                    # Send a GET request to verify the file ID
                    response = requests.get(f"{SERVER_URL}/check_file_id", json={
                        "username": username, 
                        "file_id": file_id
                    })
                    
                    # Handle the response for file ID verification
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
                file_id_flag = True  # Mark file ID selection as completed

            # Input for the new file path
            if not file_path_flag:
                file_path = input("Please input the path of the new file to replace the original one (or type \"q\" to EXIT, \"b\" to BACK):\n> ")
                if file_path == "q":
                    return False
                if file_path == "b":
                    file_id_flag = False
                    continue
                
                # Validate the new file path
                if not os.path.isfile(file_path):
                    print("[ERROR] Invalid file path or file does not exist.")
                    continue
                
                file_path_flag = True  # Mark new file path input as completed

        try:
            # Retrieve the AES key for the given username
            response = requests.get(f"{SERVER_URL}/get_aes_key", json={'username': username})
            if response.status_code == 200:
                aes_key = response.content
            elif response.status_code in [400, 401, 403]:
                response_data = response.json()
                print(response_data["message"])
                return False
            else:
                print("[ERROR] Server error.")
                return False
        except requests.exceptions.RequestException as error:
            print(f"[ERROR] Network error: {error}.")
            return False        
        
        # Encrypt the new file content using the retrieved AES key
        new_content = CryptoManager.encrypt_file_with_aes(password, aes_key, file_path)
        files = {'file': (os.path.basename(file_path), new_content.hex().encode())}
        
        try:
            # Send a POST request to edit the file
            response = requests.post(f"{SERVER_URL}/edit_file", 
                                    files=files, 
                                    data={'username': username,
                                        'file_id': file_id})
            
            # Handle the server response for file editing
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
        
        return True  # Return success
    

    @staticmethod
    def delete_file_IO(username):
        """
        Facilitates the deletion of a specified file by the user 
        after verifying the file ID.

        Parameters:
        - username: The user's username for authentication.

        Returns:
        bool: Indicates success (True) or failure (False) of the delete operation.
        """
        
        # List all (file id, file name) to facilitate user to specify the file id(s) 
        ClientIO.check_file_IO(username)
        file_id_flag = False
        file_id = None
        
        # Main loop to gather user input for the file ID to be deleted
        while not (file_id_flag):
            file_id = input("Please input the file ID for the file to be deleted (or type \"q\" to EXIT):\n> ")
            if file_id == "q":
                return False
            
            # Validate the file ID format
            if not Utils.check_file_id_regex(file_id):
                print('[ERROR] Invalid file ID format.')
                continue
            
            try:
                # Send a GET request to verify the file ID
                response = requests.get(f"{SERVER_URL}/check_file_id", json={
                    "username": username, 
                    "file_id": file_id
                })
                
                # Handle the response for file ID verification
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
            
            file_id_flag = True  # Mark file ID verification as completed

        # Prepare payload for file deletion
        payload = {'username': username, 'file_id': file_id}
        
        try:
            # Send a POST request to delete the specified file
            response = requests.post(f"{SERVER_URL}/delete_file", json=payload)
            
            # Handle the server response for file deletion
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
        
        return True  # Return success


    @staticmethod
    def share_file_IO(username, password):
        """
        Allows the user to share a specified file with other users 
        by selecting from a list of available usernames.

        Parameters:
        - username: The user's username for authentication.
        - password: The user's password used for encryption.

        Returns:
        bool: Indicates success (True) or failure (False) of the share operation.
        """
        
        # List all (file id, file name) to facilitate user to specify the file id(s) 
        ClientIO.check_file_IO(username)
        file_id_flag = False
        selected_usernames_id_flag = False
        file_id = None
        selected_usernames_id = None
        selected_usernames = []
        available_usernames = []
        
        try:
            # Send a GET request to fetch available usernames for sharing
            response = requests.get(f"{SERVER_URL}/get_users")
            if response.status_code == 200:
                response_data = response.json()
                usernames = response_data["usernames"]
                available_usernames = usernames.split(',')
                available_usernames.sort()
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
        
        # Main loop to gather user input for file sharing
        while not (file_id_flag and selected_usernames_id_flag):
            
            # Input for file ID to share
            if not file_id_flag:
                file_id = input("Please input the file ID for the file to be shared (or type \"q\" to EXIT):\n> ")
                if file_id == "q":
                    return False
                
                # Validate the file ID format
                if not Utils.check_file_id_regex(file_id):
                    print('[ERROR] Invalid file ID format.')
                    continue
                
                try:
                    # Send a GET request to verify the file ID
                    response = requests.get(f"{SERVER_URL}/check_file_id", json={
                        "username": username, 
                        "file_id": file_id
                    })
                    
                    # Handle the response for file ID verification
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
                
                file_id_flag = True  # Mark file ID verification as completed

            # Input for selecting users to share with
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
                
                selected_usernames_id_flag = True  # Mark user selection as completed

            # Fetch the file to share
            fetch_payload = {'username': username, 'file_id': file_id}
            try:
                response = requests.get(f"{SERVER_URL}/view_file", json=fetch_payload)
                if response.status_code == 200:
                    fetched_file = response.json()
                    print(fetched_file["message"])
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
            
            # Check if the file can be shared
            if fetched_file['access'] == 'shared':
                print("[ERROR] File shared from others cannot be shared again.")  
                return False    
            
            try:
                # Retrieve the AES key for the given username
                response = requests.get(f"{SERVER_URL}/get_aes_key", json={'username': username})
                if response.status_code == 200:
                    response_data = response.content
                elif response.status_code in [400, 401, 403]:
                    response_data = response.json()
                    print(response_data["message"])
                    return False
                else:
                    print("[ERROR] Server error.")
                    return False
            except requests.exceptions.RequestException as error:
                print(f"[ERROR] Network error: {error}.")
                return False
            
            # Decrypt the file content for sharing
            plaintext = CryptoManager.decrypt_file_with_aes(password, response_data, bytes.fromhex(fetched_file['content']))
            share_data = {"username": username, "file_id": file_id, 'shared_user': ''}
            
            try:
                # Share the file with selected users
                for username in selected_usernames: 
                    response = requests.get(f"{SERVER_URL}/get_rsa_key", json={'username': username})
                    user_rsa = response.content
                    encrypted_content = CryptoManager.encrypt_file_for_sharing(user_rsa, plaintext).hex().encode()
                    files = {'file': ('_', encrypted_content)}
                    share_data['shared_user'] = username
                    response = requests.post(f"{SERVER_URL}/share_file", files=files, data=share_data)
            except requests.exceptions.RequestException as error:
                print(f"[ERROR] Network error: {error}.")
                return False
            
        return True  # Return success
    
    @staticmethod
    def download_file_IO(username, password):
        """
        Downloads an existing file from the server to a specified directory
        after verifying the file ID and handling any necessary decryption.

        Parameters:
        - username: The user's username for authentication.
        - password: The user's password used for AES decryption.

        Returns:
        bool: Indicates success (True) or failure (False) of the download operation.
        """
        
        # List all (file id, file name) to facilitate user to specify the file id(s) 
        ClientIO.check_file_IO(username)
        file_id_flag = False
        stored_path_flag = False
        secret_key_flag = False
        file_id = None
        stored_path = None
        secret_key_path = None
        fetched_file = None
        
        # Main loop to gather user input for file download
        while not (file_id_flag and stored_path_flag and secret_key_flag):
            
            # Input for file ID
            if not (file_id_flag):
                file_id = input("Please input the file ID for the file to be downloaded (or type \"q\" to EXIT):\n> ")
                if file_id == "q":
                    return None
                
                # Validate the file ID format
                if not Utils.check_file_id_regex(file_id):
                    print('[ERROR] Invalid file ID format.')
                    continue
                
                try:
                    # Send a GET request to verify the file ID
                    response = requests.get(f"{SERVER_URL}/check_file_id", json={
                        "username": username, 
                        "file_id": file_id
                    })
                    
                    # Handle the response for file ID verification
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
                
                file_id_flag = True  # Mark file ID input as completed

            # Input for the target folder path to store the downloaded file
            if not (stored_path_flag):
                stored_path = input("Please input the path of the target folder for the file to be stored (or type \"q\" to EXIT, \"b\" to BACK):\n> ")
                if stored_path == "q":
                    return None
                if stored_path == "b":
                    file_id_flag = False
                    continue
                
                # Validate the directory path
                if not os.path.isdir(stored_path):
                    print("[ERROR] Invalid directory path or directory does not exist.")
                    continue
                
                payload = {'username': username, 'file_id': file_id}
                try:
                    # Send a GET request to fetch the file data
                    response = requests.get(f"{SERVER_URL}/view_file", json=payload)
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
                
                stored_path_flag = True  # Mark target path input as completed

            # Handle decryption if the file is shared
            if not (secret_key_flag):
                file_path = os.path.join(stored_path, fetched_file['file_name'])
                fetched_content = bytes.fromhex(fetched_file['content'])
                
                if fetched_file['access'] == 'shared':
                    secret_key_path = input("Please enter the file path of your secret key to decrypt, as the file is shared (or type \"q\" to EXIT, \"b\" to BACK):\n> ")
                    if secret_key_path == "q":
                        return False
                    elif secret_key_path == "b":
                        stored_path_flag = False
                        continue
                    
                    # Validate the secret key file path
                    if not os.path.isfile(secret_key_path):
                        print("[ERROR] Invalid secret_key file path or file does not exist.")
                        continue
                    
                    # Decrypt the shared file using the provided secret key
                    with open(secret_key_path, 'r') as sk:
                        CryptoManager.decrypt_shared_file(sk.read(), fetched_content, file_path)
                else:
                    # Retrieve the user's AES key for decryption
                    response = requests.get(f"{SERVER_URL}/get_aes_key", json={'username': username})
                    if response.status_code == 200:
                        response_data = response.content
                    elif response.status_code in [400, 401, 403]:
                        response_data = response.json()
                        print(response_data["message"])
                        return False
                    else:
                        print("[ERROR] Server error.")
                        return False
                    
                    # Decrypt the file using the retrieved AES key
                    CryptoManager.decrypt_file_with_aes(password, response_data, fetched_content, file_path)
                
                secret_key_flag = True  # Mark secret key handling as completed
        
        return True  # Return success


    @staticmethod
    def check_file_IO(username):
        """
        Fetches all file names in the storage that the user can read.

        Parameters:
        - username: The user's username for authentication.

        Returns:
        bool: Indicates success (True) or failure (False) of the check operation.
        """
        files = None
        try:
            # Send a GET request to fetch the user's files
            response = requests.get(f"{SERVER_URL}/get_files", json={"username": username})
            if response.status_code == 200:
                fetched_files = response.json()
                files = fetched_files['files']
                print(fetched_files["message"])
                for i in range(len(files)):
                    print(f"{i + 1}. {files[i]}")
            elif response.status_code in [400, 403]:
                response_data = response.json()
                print(response_data["message"])
                return False
            else:
                print("[ERROR] Server error.")
                return False
        except requests.exceptions.RequestException as error:
            print(f"[ERROR] Network error: {error}.")
        
        return True  # Return success


    @staticmethod
    def view_logs_IO(username):
        """
        Fetches and displays audit logs for the specified user.

        Parameters:
        - username: The user's username for authentication.

        Returns:
        bool: Indicates success (True) or failure (False) of the log retrieval operation.
        """
        try:
            # Send a GET request to fetch the user's logs
            response = requests.get(f"{SERVER_URL}/get_logs", json={"username": username})
            if response.status_code == 200:
                response_data = response.json()
                print(response_data["message"])
                logs = response_data["logs"]
                if not logs:
                    print("[STATUS] No logs available.")
                else:
                    print("[LOGS] Audit Logs:")
                    for log in logs:
                        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(log["timestamp"]))
                        print(f"- {timestamp} | User: {log['username']} | Action: {log['action']} | Details: {log['details']} | Status: {log['status']}")
            elif response.status_code == 400:
                response_data = response.json()
                print(response_data["message"])
                return False
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
        
        return True  # Return success