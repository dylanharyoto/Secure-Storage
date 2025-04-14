from flask import Response, Flask, request, jsonify, g
import sqlite3
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from sourcecode.Server import config
from sourcecode.Shared.Utils import Utils
from sourcecode.Server.FileManager import FileManager
from sourcecode.Server.UserManager import UserManager
from sourcecode.Server.OTPManager import OTPManager, OTPMessage
from sourcecode.Server.PendingManager import PendingManager
from sourcecode.Server.LogManager import LogManager

# import (default) configurations from the /Server/config.py
app = Flask(__name__)
app.config[config.USERS_DB] = os.path.join(os.path.dirname(__file__), "Database", "users.db")
app.config[config.FILES_DB] = os.path.join(os.path.dirname(__file__), "Database", "files.db")
app.config[config.OTPS_DB] = os.path.join(os.path.dirname(__file__), "Database", "otps.db")
app.config[config.PENDINGS_DB] = os.path.join(os.path.dirname(__file__), "Database", "pendings.db")
app.config[config.LOGS_DB] = os.path.join(os.path.dirname(__file__), "Database", "logs.db")
os.makedirs(config.DB_DIR, exist_ok=True)

# define schema of databases 
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
otps_schema = {
    "username": "TEXT NOT NULL",
    "otp_type": "TEXT NOT NULL",
    "otp": "TEXT NOT NULL",
    "timestamp": "INTEGER NOT NULL"
}
pendings_schema = {
    "username": "TEXT PRIMARY KEY",
    "password": "BLOB NOT NULL",
    "encrypted_aes_key": "BLOB NOT NULL",
    "public_key": "BLOB NOT NULL"
}
logs_schema = {
    "log_id": "INTEGER PRIMARY KEY AUTOINCREMENT",
    "timestamp": "INTEGER NOT NULL",
    "username": "TEXT NOT NULL",
    "action": "TEXT NOT NULL",
    "details": "TEXT",
    "status": "TEXT NOT NULL"
}

# import (default) configurations from the /Server/config.py
Utils.init_db(app.config[config.USERS_DB], "users", users_schema)
Utils.init_db(app.config[config.FILES_DB], "files", files_schema)
Utils.init_db(app.config[config.OTPS_DB], "otps", otps_schema)
Utils.init_db(app.config[config.PENDINGS_DB], "pendings", pendings_schema)
Utils.init_db(app.config[config.LOGS_DB], "logs", logs_schema)

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

@app.route('/get_logs', methods=['GET'])
def get_logs():
    """(only applicable for the administrator account) Get the logs of all users' sensitive actions from the server"""
    data = request.json
    username = data.get('username')
    if not (username):
        try:
            if not LogManager.log_action(get_db(config.LOGS_DB), username or "unknown", "access_logs", "Missing username", "failure"):
                return jsonify({"message": "[ERROR] Missing username."}), 400
        except Exception as error:
            return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    if username != config.ADMIN_USER:
        try:
            LogManager.log_action(get_db(config.LOGS_DB), username, "access_logs", "Failed to access logs: unauthorized", "failure")
        except Exception as error:
            return jsonify({"message": f"[ERROR] {str(error)}."}), 403
        return jsonify({"message": "[ERROR] Unauthorized access."}), 403
    try:
        LogManager.log_action(get_db(config.LOGS_DB), username or "admin", "access_logs", "Accessed logs successfully", "success")
    except Exception as error:
            return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    try:
        logs = LogManager.get_logs(get_db(config.LOGS_DB))
    except Exception as error:
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    log_list = [{"timestamp": row[0], "username": row[1], "action": row[2], "details": row[3], "status": row[4]} for row in logs]
    return jsonify({"message": "[STATUS] Logs fetched successfully.", "logs": log_list}), 200

@app.route('/check_username', methods=['GET'])
def check_username():
    """check if a username is already registered in the server"""
    data = request.json
    username = data.get('username')
    if not (username):
        return jsonify({"message": "[ERROR] Missing username."}), 400
    try:
        if not UserManager.check_username(get_db(config.USERS_DB), username):
            return jsonify({"message": "[STATUS] Email does not exist yet."}), 201
    except Exception as error:
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    return jsonify({"message": "[STATUS] Email already exists."}), 200

@app.route('/get_password', methods=['GET'])
def get_password():
    """Get the hashed password of the specified username for client to compare with plaintext input password for authentication"""
    # Here, the get_password API is just to retrieved the stored hashA in server users database
    data = request.json
    username = data.get('username')
    if not (username):
        return jsonify({"message": "[ERROR] Missing username."}), 400
    try:
        if not UserManager.check_username(get_db(config.USERS_DB), username):
            return jsonify({"message": f"[ERROR] {username} has not registered yet."}), 201
    except Exception as error:
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    hashed_password = UserManager.get_password(get_db(config.USERS_DB), username)
    return jsonify({"message":"[STATUS] Hashed password fetched successfully.", "hashed_password": hashed_password}), 200

@app.route('/get_registration_otp', methods=['GET'])
def get_registration_otp():
    """
    Send the registration OTP opon a user's registration 
    """
    username = request.form.get('username')
    password = request.form.get('password')
    public_key = request.form.get('public_key')
    encrypted_aes_key = request.files.get('encrypted_aes_key').read()
    if not (username and password and public_key and encrypted_aes_key):
        return jsonify({"message": "[ERROR] Missing username or password or public key or encrypted aes key."}), 400
    try:
        PendingManager.store_pending(get_db(config.PENDINGS_DB), username, password, encrypted_aes_key, public_key)
    except Exception as error:
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    otp = OTPManager.generate_otp()
    try:
        OTPManager.store_otp(get_db(config.OTPS_DB), username, 'registration', otp)
    except Exception as error:
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    OTPManager.send_otp(username, otp)
    return jsonify({"message": "[STATUS] OTP sent to your email. Please check it."}), 200

@app.route('/verify_registration_otp', methods=['POST'])
def verify_registration_otp():
    """
    Verify the registration OTP opon a user's registration to confirm the username as a valid email address for the following 2FA in login
    """
    data = request.json
    username = data.get('username')
    otp = data.get('otp')
    if not (username and otp):
        return jsonify({"message": "[ERROR] Missing username or OTP."}), 400
    try:
        success, message = OTPManager.verify_otp(get_db(config.OTPS_DB), username, 'registration', otp)
    except Exception as error:
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    if not success:
        if message == OTPMessage.INVALID:
            return jsonify({"message": f"[ERROR] {message.value}."}), 201
        else:
            return jsonify({"message": f"[ERROR] {message.value}."}), 202
    try:
        password, encrypted_aes_key, public_key = PendingManager.get_pending(get_db(config.PENDINGS_DB), username)
    except Exception as error:
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    try:
        UserManager.register_user(get_db(config.USERS_DB), username, password, encrypted_aes_key, public_key)
    except Exception as error:
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    PendingManager.delete_pending(get_db(config.PENDINGS_DB), username)
    return jsonify({"message": f"[STATUS] Email '{username}' registered successfully."}), 200

@app.route('/get_login_otp', methods=['GET'])
def get_login_otp():
    """send the login OTP after user's password is vaidated to serve as 2FA"""
    data = request.json
    username = data.get('username')
    if not (username):
        return jsonify({"message": "[ERROR] Missing username."}), 400
    otp = OTPManager.generate_otp()
    try:
        OTPManager.store_otp(get_db(config.OTPS_DB), username, 'login', otp)
    except Exception as error:
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    OTPManager.send_otp(username, otp)
    return jsonify({"message": "[STATUS] OTP sent to your email. Please enter the OTP to confirm login."}), 200

@app.route('/verify_login_otp', methods=['POST'])
def verify_login_otp():
    """verify the login OTP"""
    data = request.json
    username = data.get('username')
    otp = data.get('otp')
    if not (username and otp):
        LogManager.log_action(get_db(config.LOGS_DB), username or "unknown", "login", "Missing username or OTP", "failure")
        return jsonify({"message": "[ERROR] Missing username or OTP."}), 400
    try:
        success, message = OTPManager.verify_otp(get_db(config.OTPS_DB), username, 'login', otp)
    except Exception as error:
        LogManager.log_action(get_db(config.LOGS_DB), username, "login", f"Login failed: {str(error)}", "failure")
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    if not success:
        LogManager.log_action(get_db(config.LOGS_DB), username, "login", f"Login failed: {message.value}", "failure")
        if message == OTPMessage.INVALID:
            return jsonify({"message": f"[ERROR] {message.value}."}), 201
        else:
            return jsonify({"message": f"[ERROR] {message.value}."}), 202
    LogManager.log_action(get_db(config.LOGS_DB), username, "login", "Logged in successfully", "success")
    return jsonify({"message": f"[STATUS] Email '{username}' logged in successfully."}), 200

@app.route('/get_reset_otp', methods=['GET'])
def get_reset_otp():
    """send the OTP to a user's email for resetting password after confirming the recovery_key is correct"""
    data = request.json
    username = data.get('username')
    if not username:
        return jsonify({"message": "[ERROR] Missing username."}), 400
    otp = OTPManager.generate_otp()
    try:
        OTPManager.store_otp(get_db(config.OTPS_DB), username, 'reset', otp)
    except Exception as error:
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    OTPManager.send_otp(username, otp)
    return jsonify({"message": "OTP sent to your email. Please enter the OTP to reset password."}), 200

@app.route('/verify_reset_otp', methods=['POST'])
def verify_reset_otp():
    """validate the resetting password OTP"""
    username = request.form.get('username')
    otp = request.form.get('otp')
    new_password = request.form.get('new_password')  
    new_aes_key = request.files.get('new_aes_key').read()
    if not (username and otp and new_password and new_aes_key):
        return jsonify({"message": "[ERROR] Missing required fields."}), 400
    try:
        success, message = OTPManager.verify_otp(get_db(config.OTPS_DB), username, 'reset', otp)
    except Exception as error:
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    if not success:
        if message == OTPMessage.INVALID:
            return jsonify({"message": f"[ERROR] {message.value}."}), 201
        else:
            return jsonify({"message": f"[ERROR] {message.value}."}), 202
    try:
        UserManager.reset_password(get_db(config.USERS_DB), username, new_password, new_aes_key)
    except Exception as error:
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    return jsonify({"message": f"[STATUS] Password for '{username}' reset successfully."}), 200

@app.route('/check_file_id', methods=['GET'])
def check_file_id():
    """check the file id is existed in the files database or not"""
    username = request.json.get('username')
    file_id = request.json.get('file_id')
    if not (username and file_id):
        return jsonify({"message": "[ERROR] Missing username or file."}), 400
    try:
        result = FileManager.check_file_id(get_db(config.FILES_DB), username, file_id)
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
        LogManager.log_action(get_db(config.LOGS_DB), username or "unknown", "upload_file", "Missing username or file", "failure")
        return jsonify({"message": "[ERROR] Missing username or file."}), 400
    try:
        file_data = bytes.fromhex(file.read().decode())
        file_id = FileManager.upload_file(get_db(config.FILES_DB), username, file.filename, file_data)
    except Exception as error:
        LogManager.log_action(get_db(config.LOGS_DB), username, "upload_file", f"Failed to upload file: {str(error)}", "failure")
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    LogManager.log_action(get_db(config.LOGS_DB), username, "upload_file", f"Uploaded file '{file.filename}' with file_id: {file_id}", "success")
    return jsonify({"message": f"[STATUS] File '{file.filename}' uploaded successfully.", "file_id": file_id}), 200


@app.route('/edit_file', methods=['POST'])
def edit_file():
    """Edit a file (only if owned by the requester)"""
    username = request.form.get('username')
    file_id = request.form.get('file_id')
    new_file = request.files.get('file')
    if not (username and file_id and new_file):
        LogManager.log_action(get_db(config.LOGS_DB), username or "unknown", "edit_file", "Missing username or file_id or new_file", "failure")
        return jsonify({"message": "[ERROR] Missing username or file_id or new_file."}), 400
    try:
        file_data = bytes.fromhex(new_file.read().decode())
        FileManager.edit_file(get_db(config.FILES_DB), username, new_file.filename, file_id, file_data) # to be changed when FileManager is static
    except Exception as error:
        LogManager.log_action(get_db(config.LOGS_DB), username, "edit_file", f"Failed to edit file: {str(error)}", "failure")
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    LogManager.log_action(get_db(config.LOGS_DB), username, "edit_file", f"Edited file with file_id: {file_id}", "success")
    return jsonify({"message": "f[STATUS] File '{file_id}' uploaded successfully."}), 200


@app.route('/delete_file', methods=['POST'])
def delete_file():
    """Delete a file (only if owned by the requester)"""
    username = request.json.get('username')
    file_id = request.json.get('file_id')
    if not (username and file_id):
        LogManager.log_action(get_db(config.LOGS_DB), username or "unknown", "delete_file", "Missing username or file_id", "failure")
        return jsonify({"message": "[ERROR] Missing username or file_id."}), 400
    try:
        FileManager.delete_file(get_db(config.FILES_DB), username, file_id) # to be changed when FileManager is static
    except Exception as error:
        LogManager.log_action(get_db(config.LOGS_DB), username, "delete_file", f"Failed to delete file: {str(error)}", "failure")
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    LogManager.log_action(get_db(config.LOGS_DB), username, "delete_file", f"Deleted file with file_id: {file_id}", "success")
    return jsonify({"message": f"[STATUS] File '{file_id}' deleted successfully."}), 200


@app.route('/share_file', methods=['POST'])
def share_file():
    """
    Share a file
    Expected JSON payload:
    {
        "username": "alice",
        "file_id": "original_file_id",
        "share_info": {
            "bob": "Bob's shared file content (hex)",
            "carol": "Carol's shared file content (hex)"
        }
    }
    """
    username = request.form.get('username')
    file_id = request.form.get('file_id')
    shared_user = request.form.get('shared_user')
    shared_file = request.files.get('file')
    shared_data = bytes.fromhex(shared_file.read().decode())
    if not (username and file_id and shared_user and shared_data):
        LogManager.log_action(get_db(config.LOGS_DB), username or "unknown", "share_file", "Missing username or file_id or share_info", "failure")
        return jsonify({"message": "[ERROR] Missing username or file_id or share_info."}), 400
    try:
        new_id = FileManager.share_file(get_db(config.FILES_DB), username, file_id, shared_user, shared_data) # to be chnaged when FileManager is static
    except Exception as error:
        LogManager.log_action(get_db(config.LOGS_DB), username, "share_file", f"Failed to share file: {str(error)}", "failure")
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    LogManager.log_action(get_db(config.LOGS_DB), username, "share_file", f"Shared file with file_id: {file_id} to user: {shared_user}", "success")
    return jsonify({"message":"", "shared_file_id": new_id}), 200

@app.route('/get_files', methods=['GET'])
def get_files():
    """Get all files (i.e., the list of triples: (fileID, fileName, access))for a user"""
    username = request.json.get('username')
    if not username:
        return jsonify({"message": "[ERROR] Missing username."}), 400
    try:
        files = FileManager.get_files(get_db(config.FILES_DB), username)
    except Exception as error:
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    return jsonify({"message": f"[STATUS] Files for {username} fetched successfully.", "files": files}), 200


@app.route('/view_file', methods=['GET'])
def view_file():
    """View (Download) a file's encrypted content"""
    username = request.json.get('username')
    file_id = request.json.get('file_id')
    if not (username and file_id):
        return jsonify({"message": "[ERROR] Missing username or file_id."}), 400
    try:
        content, access, file_name = FileManager.view_file(get_db(config.FILES_DB), username, file_id)
       
    except Exception as error:
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    return jsonify({"message":f"[STATUS] File '{file_id}' fetched successfully.", "content": content.hex(), "access": access, "file_name": file_name}), 200
    

@app.route('/get_users', methods=['GET'])
def get_users():
    """Get the list of users"""
    usernames = None
    try:
        usernames = FileManager.get_users(get_db(config.USERS_DB))
    except Exception as error:
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    usernames = ",".join(usernames)
    return jsonify({"message": "Fetched all users successfully.", "usernames": usernames}), 200


@app.route('/get_aes_key', methods=['GET'])
def get_aes_key():
    """Get Encrypted AES key of the specified user"""
    username = request.json.get('username')
    if not (username):
        return jsonify({"message": "[ERROR] Missing username."}), 400
    try:
        aes_key = FileManager.get_aes_key(get_db(config.USERS_DB), username) 
    except Exception as error:
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    if not aes_key:
        return jsonify({"message": f"[ERROR] AES key for {username} is not found."}), 401
    return Response(aes_key, mimetype='application/octet-stream'), 200
    


@app.route('/get_rsa_key', methods=['GET'])
def get_rsa_key():
    """Get the public key of the specified user to encrypt a shared_file"""
    username = request.json.get('username')
    if not (username):
        return jsonify({"message": "[ERROR] Missing username."}), 400
    try:
        rsa_key = FileManager.get_rsa_key(get_db(config.USERS_DB), username) 
    except Exception as error:
        return jsonify({"message": f"[ERROR] {str(error)}."}), 403
    if not rsa_key:
        return jsonify({"message": f"[ERROR] RSA key for {username} is not found."}), 401
    return Response(rsa_key, mimetype='application/octet-stream'), 200
   

if __name__ == "__main__":
    # By default, the server is running on 5100 port and hosted on 0.0.0.0
    app.run(host="0.0.0.0", port=5100, debug=True)