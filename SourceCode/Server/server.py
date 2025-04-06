from flask import Flask, request, jsonify, g
import sqlite3
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from SourceCode.Shared.Utils import Utils
from SourceCode.Server.FileManager import FileManager
from SourceCode.Server.UserManager import UserManager

# Table Names for g
USERS_DB = "USERS_DB"
FILES_DB = "FILES_DB"
# Table Names for g

# Table Schemas
users_schema = {
    "username": "TEXT PRIMARY KEY",
    "password": "BLOB NOT NULL",
    "encrypted_aes_key": "BLOB NOT NULL",
    "public_key": "BLOB NOT NULL"
}
files_schema = {
    "file_id": "TEXT PRIMARY KEY",
    "owner": "TEXT NOT NULL",
    "file_name": "TEXT NOT NULL",
    "access": "TEXT NOT NULL",
    "content": "BLOB NOT NULL"
}
# Table Schemas

# Initialization
app = Flask(__name__)
app.config[USERS_DB] = os.path.join(os.path.dirname(__file__), "Database", "Users.db")
app.config[FILES_DB] = os.path.join(os.path.dirname(__file__), "Database", "Files.db")
os.makedirs(os.path.dirname(app.config[USERS_DB]), exist_ok=True)
os.makedirs(os.path.dirname(app.config[FILES_DB]), exist_ok=True)
Utils.init_db(app.config[USERS_DB], "Users", users_schema)
Utils.init_db(app.config[FILES_DB], "Files", files_schema)
# Initialization

def get_db(config_key):
    """Get a database connection for the current request."""
    db_attr = f'db_{config_key.lower()}'
    if db_attr not in g:
        setattr(g, db_attr, sqlite3.connect(app.config[config_key]))
    return getattr(g, db_attr)

@app.teardown_appcontext
def close_db(exception = None):
    """Close the database connection at the end of each request."""
    for attr in list(g.__dict__.keys()):
        if attr.startswith("db_") and attr.endswith("_db"):
            getattr(g, attr).close()
            delattr(g, attr)

@app.route('/check_username', methods=['POST'])
def check_username():
    data = request.json
    username = data.get('username')
    print(username)
    if UserManager.check_username(get_db(USERS_DB), username):
        return jsonify({"message": "[STATUS] Email exists."}), 200
    return jsonify({"message": "[STATUS] Email does not exist yet."}), 201

@app.route('/register_user', methods=['POST'])
def register_user():

    username = request.form.get('username')
    password = request.form.get('password')
    public_key = request.form.get('public_key')
    encrypted_aes_key = request.files.get('encrypted_aes_key').read()
    if UserManager.register_user(get_db(USERS_DB), username, password, encrypted_aes_key, public_key):
        return jsonify({"message": f"[STATUS] Email '{username}' registered successfully."}), 200
    return jsonify({"message": f"[ERROR] Email '{username}' failed to be registered."}), 400
    

@app.route('/login_user', methods=['POST'])
def login_user():
    # Here, the login_user API is just to retrieved the stored hashA in server users database
    data = request.json
    username = data.get('username')
    password = data.get('password')
    hashed_password = UserManager.login_user(get_db(USERS_DB), username, password)
    if UserManager.login_user(get_db(USERS_DB), username, password):
        return jsonify({"message":"", "hashed_password": hashed_password}), 200
    return jsonify({"message": f"[ERROR] {username} has not registered yet."}), 201

@app.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.json
    username = data.get('username')
    new_password = data.get('new_password')
    new_aes_key = data.get('new_aes_key')
    #new_hashed_password = Utils.hash_password(new_password)
    if UserManager.reset_password(get_db(USERS_DB), username, new_password, new_aes_key):
        return jsonify({"message": f"[STATUS] Password for '{username}' reset successfully."}), 200
    return jsonify({"message": f"[ERROR] Password for '{username}' failed to be reset."}), 400


@app.route('/check_file_id', methods=['POST'])
def check_file_id():
    data = request.json
    username = data.get('username')
    file_id = data.get('file_id')
    if not (username and file_id):
        return jsonify({"message": "[ERROR] Missing username or file."}), 400
    try:
        result = FileManager.check_file_id(get_db(USERS_DB), username, file_id)
    except Exception as error:
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    if not result:
        return jsonify({"message": "[STATUS] File ID does not exist."}), 201
    return jsonify({"message": "[STATUS] File ID exists."}), 200

# Endpoint: Upload a file
@app.route('/upload_file', methods=['POST'])
def upload_file():
    username = request.form.get('username')
    file = request.files.get('file')
    if not (username and file):
        return jsonify({"message": "[ERROR] Missing username or file."}), 400
    try:
        file_id = FileManager.upload_file(get_db(FILES_DB), username, file.filename, file.read())
    except Exception as error:
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    return jsonify({"message": f"[STATUS] File '{file.filename}' uploaded successfully.", "file_id": file_id}), 200

# Endpoint: Edit a file (only if owned by the requester)
@app.route('/edit_file', methods=['POST'])
def edit_file():
    username = request.json.get('username')
    file_id = request.json.get('file_id')
    new_content = request.json.get('content')
    if not (username and file_id and new_content):
        return jsonify({"message": "[ERROR] Missing username or file_id or new_content."}), 400
    try:
        FileManager.edit_file(username, file_id, new_content.encode()) # to be chnaged when FileManager is static
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
        FileManager.delete_file(get_db(FILES_DB), username, file_id) # to be chnaged when FileManager is static
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
        new_ids = FileManager.share_file(get_db(FILES_DB), username, file_id, share_info) # to be chnaged when FileManager is static
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
        files = FileManager.get_files(get_db(FILES_DB), username)
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
        content, access = FileManager.view_file(get_db(FILES_DB), username, file_id)
        # Assuming text content; adjust if binary data (e.g., use base64 encoding)
    except Exception as error:
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    return jsonify({"message":f"[STATUS] File '{file_id}' fetched successfully.", "content": content.decode(), "access": access}), 200
    
# Endpoint: Get users
@app.route('/get_users', methods=['POST'])
def get_users():
    usernames = None
    try:
        usernames = FileManager.get_users(get_db(USERS_DB))
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
        aes_key = FileManager.get_aes_key(get_db(USERS_DB), username) # to be changed when FileManager is static
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
        rsa_key = FileManager.get_rsa_key(get_db(USERS_DB), username) # to be changed when FileManager is static
    except Exception as error:
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    if not rsa_key:
        return jsonify({"message": f"[ERROR] RSA key for {username} is not found."}), 401
    return jsonify({"message": f"[STATUS] RSA key for {username} exists.", "rsa_key": rsa_key}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5100, debug=True)