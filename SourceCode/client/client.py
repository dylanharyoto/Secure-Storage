import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from SourceCode.client.user_management import UserManagement

class Client:
    def __init__(self):
        self.user_management = UserManagement()
        self.run()

    def run(self):
        while True:
            print("\nUser Management Menu:")
            print("1. Register User")
            print("2. Log In")
            print("3. Reset Password")
            print("4. Exit")
            choice = input("Enter your choice:\n> ").strip()
            if choice == "1":
                client_aes = self.user_management.register_user_IO()
                if client_aes:
                    print(f"[INFO] Client AES key generated: {client_aes}")
            elif choice == "2":
                status = self.user_management.login_user_IO()
                if status[0]:
                    print("[INFO] Login successful.")
                    self.session(status[1])
            elif choice == "3":
                status = self.user_management.reset_password_IO()
                if status:
                    print("[INFO] Password reset successful.")
            elif choice == "4":
                print("Exiting User Management...")
                break
            else:
                print("Invalid choice. Please try again.")
    
    
    def session(self, username):
        while True:
            print("\nHome Page:")
            print("1. View Storage")
            print("2. Upload File")
            print("3. Download File")
            print("4. Peek File")
            print("5. Edit File")
            choice = input("Enter your choice:\n> ").strip()
            if choice == "1":
                self.user_management.user_read_storage(username)
            elif choice == "2":
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

if __name__ == "__main__":
    client = Client()
    client.run()