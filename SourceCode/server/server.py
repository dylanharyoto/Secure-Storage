from flask import Flask, request, jsonify, g
import sqlite3
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from SourceCode.Shared.Utils import Utils
from SourceCode.Server.FileManager import FileManager
from SourceCode.Server.UserManager import UserManager


app = Flask(__name__)
app.config['USERS_DATABASE'] = os.path.join(os.path.dirname(__file__), "data", "Users.db")
app.config['FILES_DATABASE'] = os.path.join(os.path.dirname(__file__), "data", "Files.db")
file_manager = FileManager()
os.makedirs(os.path.dirname(app.config['USERS_DATABASE']), exist_ok=True)
os.makedirs(os.path.dirname(app.config['FILES_DATABASE']), exist_ok=True)
users_schema = {
    "username": "TEXT PRIMARY KEY",
    "password": "TEXT NOT NULL",
    "encrypted_aes_key": "TEXT NOT NULL",
    "public_key": "TEXT NOT NULL"
}
files_schema = {
    "file_id": "TEXT PRIMARY KEY",
    "owner": "TEXT NOT NULL",
    "file_name": "TEXT NOT NULL",
    "access": "TEXT NOT NULL",
    "content": "BLOB NOT NULL"
}
Utils.init_database(app.config['USERS_DATABASE'], "Users", users_schema)
Utils.init_database(app.config['FILES_DATABASE'], "Files", files_schema)


def get_db(config_key):
    """Get a database connection for the current request."""
    db_attr = f'db_{config_key.lower()}'
    if db_attr not in g:
        setattr(g, db_attr, sqlite3.connect(app.config[config_key]))
    return getattr(g, db_attr)

@app.teardown_appcontext
def close_db():
    """Close the database connection at the end of each request."""
    for attr in list(g.__dict__.keys()):
        if attr.startswith("db_"):
            getattr(g, attr).close()
            delattr(g, attr)

@app.route('/check_username', methods=['POST'])
def check_username():
    data = request.json
    username = data.get('username')
    if UserManager.check_username(get_db('USERS_DATABASE'), username):
        return jsonify({"message": "[STATUS] Email exists."}), 200
    return jsonify({"message": "[STATUS] Email does not exist yet."}), 201

@app.route('/register_user', methods=['POST'])
def register_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    encrypted_aes_key = data.get('encrypted_aes_key')
    public_key = data.get('public_key')
    if UserManager.register_user(get_db("USERS_DATABASE"), username, password, encrypted_aes_key, public_key):
        return jsonify({"message": f"[STATUS] Email '{username}' registered successfully."}), 200
    return jsonify({"message": f"[ERROR] Email '{username}' failed to be registered."}), 400
    

@app.route('/login_user', methods=['POST'])
def login_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if UserManager.login_user(get_db("USERS_DATABASE"), username, password):
        return jsonify({"message": f"[STATUS] Email '{username}' logged in successfully."}), 200
    return jsonify({"message": "[ERROR] Incorrect password."}), 201

@app.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.json
    username = data.get('username')
    new_password = data.get('new_password')
    new_aes_key = data.get('new_aes_key')
    #new_hashed_password = Utils.hash_password(new_password)
    if UserManager.reset_password(get_db("USERS_DATABASE"), username, new_password, new_aes_key):
        return jsonify({"message": f"[STATUS] Password for '{username}' reset successfully."}), 200
    return jsonify({"message": f"[ERROR] Password for '{username}' failed to be reset."}), 400

# Endpoint: Upload a file
@app.route('/upload_file', methods=['POST'])
def upload_file():
    username = request.form.get('username')
    file = request.files.get('file')
    if not (username and file):
        return jsonify({"message": "[ERROR] Missing username or file."}), 400
    try:
        file_id = file_manager.add_file(username, file.file_name, file.read()) # change file.filename to file.file_name
    except Exception as error:
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    return jsonify({"message": f"[STATUS] File '{username}' uploaded successfully.", "file_id": file_id}), 200

# Endpoint: Edit a file (only if owned by the requester)
@app.route('/edit_file', methods=['POST'])
def edit_file():
    username = request.json.get('username')
    file_id = request.json.get('file_id')
    new_content = request.json.get('content')
    if not (username and file_id and new_content):
        return jsonify({"message": "[ERROR] Missing username or file_id or new_content."}), 400
    try:
        file_manager.edit_file(username, file_id, new_content.encode()) # to be chnaged when file_manager is static
    except Exception as error:
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    return jsonify({"message": "f[STATUS] File '{file_id}' uploaded successfully."}), 200

# Endpoint: Delete a file (only if owned by the requester)
@app.route('/delete_file', methods=['POST'])
def delete_file():
    username = request.json.get('username')
    file_id = request.json.get('file_id')
    if not (username and file_id):
        return jsonify({"message": "[ERROR] Missing username or file_id."}), 400
    try:
        file_manager.delete_file(username, file_id) # to be chnaged when file_manager is static
    except Exception as error:
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    return jsonify({"message": f"[STATUS] File '{file_id}' deleted successfully."}), 200

# Endpoint: Share a file
@app.route('/share_file', methods=['POST'])
def share_file():
    """
    Expected JSON payload:
    {
        "username": "alice",
        "file_id": "original_file_id",
        "share_info": {
            "bob": "Bob's shared file content (base64 or text)",
            "carol": "Carol's shared file content"
        }
    }
    """
    username = request.json.get('username')
    file_id = request.json.get('file_id')
    share_info = request.json.get('share_info')
    if not (username and file_id and share_info):
        return jsonify({"message": "[ERROR] Missing username or file_id or share_info."}), 400
    try:
        new_ids = file_manager.share_file(username, file_id, share_info) # to be chnaged when file_manager is static
        return jsonify({"message":"", "shared_file_ids": new_ids}), 200
    except Exception as error:
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403

# Endpoint: Get all files for a user
@app.route('/get_files', methods=['POST'])
def get_files():
    username = request.json.get('username')
    if not username:
        return jsonify({"message": "[ERROR] Missing username."}), 400
    try:
        files = file_manager.get_files(username)
    except Exception as error:
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    return jsonify({"message": f"[STATUS] Files for {username} fetched successfully.", "files": files}), 200

# Endpoint: View a file's content
@app.route('/view_file', methods=['POST'])
def view_file():
    username = request.json.get('username')
    file_id = request.json.get('file_id')
    if not (username and file_id):
        return jsonify({"message": "[ERROR] Missing username or file_id."}), 400
    try:
        content, access = file_manager.view_file(username, file_id)
        # Assuming text content; adjust if binary data (e.g., use base64 encoding)
    except Exception as error:
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    return jsonify({"message":f"[STATUS] File '{file_id}' fetched successfully.", "content": content.decode(), "access": access}), 200
    
# Endpoint: Get users
@app.route('/get_users', methods=['POST'])
def get_users():
    usernames = None
    try:
        usernames = file_manager.get_users()
    except Exception as error:
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    usernames = ",".join(usernames)
    return jsonify({"message": "Fetched all users successfully.", "usernames": usernames}), 200


# Endpoint: Get AES key
@app.route('/get_aes_key', methods=['POST'])
def get_aes_key():
    username = request.json.get('username')
    if not (username):
        return jsonify({"message": "[ERROR] Missing username."}), 400
    try:
        aes_key = file_manager.get_aes_key(username) # to be changed when file_manager is static
    except Exception as error:
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    if not aes_key:
        return jsonify({"message": f"[ERROR] AES key for {username} is not found."}), 401
    return jsonify({"message": f"[STATUS] AES key for {username} exists.", "aes_key": aes_key}), 200

# Endpoint: Get RSA key
@app.route('/get_rsa_key', methods=['POST'])
def get_rsa_key():
    username = request.json.get('username')
    if not (username):
        return jsonify({"message": "[ERROR] Missing username."}), 400
    try:
        rsa_key = file_manager.get_rsa_key(username) # to be changed when file_manager is static
    except Exception as error:
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    if not rsa_key:
        return jsonify({"message": f"[ERROR] RSA key for {username} is not found."}), 401
    return jsonify({"message": f"[STATUS] RSA key for {username} exists.", "rsa_key": rsa_key}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5100, debug=True)