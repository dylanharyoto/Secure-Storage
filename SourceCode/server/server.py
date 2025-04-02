from flask import Flask, request, jsonify, g
import sqlite3
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from SourceCode.shared.utils import hash_password, init_database, check_password  # Import check_password
from file_manager import FileManager

# Initialize Flask app
app = Flask(__name__)
app.config['DATABASE'] = os.path.join(os.path.dirname(__file__), "data", "users.db")
file_manager = FileManager()

# Initialize the database before the app starts
db_file_name = app.config['DATABASE']
os.makedirs(os.path.dirname(db_file_name), exist_ok=True)
init_database(db_file_name, "users")

def get_db():
    """Get a database connection for the current request."""
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
    return g.db

@app.teardown_appcontext
def close_db(error):
    """Close the database connection at the end of each request."""
    if hasattr(g, 'db'):
        g.db.close()

@app.route('/check_username', methods=['POST'])
def check_username():
    data = request.json
    username = data.get('username')
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    exists = cursor.fetchone() is not None
    if exists:
        return jsonify({"message": "username exists"}), 201
    return jsonify({"message": "username does not exist"}), 200

@app.route('/register_user', methods=['POST'])
def register_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    encrypted_aes_key = data.get('encrypted_aes_key')
    public_key = data.get('public_key')
    db = get_db()
    cursor = db.cursor()
    hashed_password = hash_password(password)
    cursor.execute(
        "INSERT INTO users (username, password, encrypted_aes_key, public_key) VALUES (?, ?, ?, ?)",
        (username, hashed_password, encrypted_aes_key, public_key)
    )
    db.commit()
    return jsonify({"message": "Registered Successfully"}), 200

@app.route('/login_user', methods=['POST'])
def login_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    stored_hash = result[0]
    if check_password(password, stored_hash):
        return jsonify({"message": "password matches"}), 200
    return jsonify({"message": "password does not match"}), 201

@app.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.json
    username = data.get('username')
    new_password = data.get('new_password')
    db = get_db()
    cursor = db.cursor()
    new_hashed_password = hash_password(new_password)
    cursor.execute(
        "UPDATE users SET password = ? WHERE username = ?",
        (new_hashed_password, username)
    )
    db.commit()
    return jsonify({"message": "password reset"}), 200

# Endpoint: Upload a file
@app.route('/upload_file', methods=['POST'])
def upload_file():
    username = request.form.get('username')
    file = request.files.get('file')
    if not username or not file:
        return jsonify({"error": "Missing username or file"}), 400

    file_id = file_manager.add_file(username, file.filename, file.read())
    return jsonify({"file_id": file_id})


# Endpoint: Edit a file (only if owned by the requester)
@app.route('/edit_file', methods=['POST'])
def edit_file():
    username = request.json.get('username')
    file_id = request.json.get('file_id')
    new_content = request.json.get('content')
    try:
        file_manager.edit_file(username, file_id, new_content.encode())
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 403

# Endpoint: Delete a file (only if owned by the requester)
@app.route('/delete_file', methods=['POST'])
def delete():
    username = request.json.get('username')
    file_id = request.json.get('file_id')
    try:
        file_manager.delete_file(username, file_id)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 403

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
    if not username or not file_id or not share_info:
        return jsonify({"error": "Missing username, file_id, or share_info"}), 400
    try:
        new_ids = file_manager.share_file(username, file_id, share_info)
        return jsonify({"shared_file_ids": new_ids})
    except Exception as e:
        return jsonify({"error": str(e)}), 403
      
# Endpoint: View all files for a user
@app.route('/view_file', methods=['POST'])
def view_file():
    username = request.json.get('username')
    if not username:
        return jsonify({"error": "Missing username"}), 400
    try:
        files = file_manager.view_file(username)
        return jsonify({"files": files})
    except Exception as e:
        return jsonify({"error": str(e)}), 403

# Endpoint: Get a file's content

@app.route('/get_file', methods=['POST'])
def get_file():
    username = request.json.get('username')
    file_id = request.json.get('file_id')
    if not username or not file_id:
        return jsonify({"error": "Missing username or file_id"}), 400
    try:
        content, access = file_manager.get_file(username, file_id)
        # Assuming text content; adjust if binary data (e.g., use base64 encoding)
        return jsonify({"content": content.decode(), "access": access})
    except Exception as e:
        return jsonify({"error": str(e)}), 403



# Endpoint: Require AES key
@app.route('/get_aes', methods=['POST'])
def get_aes():
    username = request.form.get('username')
    user_aes = file_manager.get_user_aes(username)
    if not user_aes:
        return jsonify({"error": f"AES key for {username} not found"}), 400
    return jsonify({"aes": user_aes})

# Endpoint: Require RSA key
@app.route('/require_rsa', methods=['POST'])
def require_rsa():
    username = request.form.get('username')
    user_rsa = file_manager.get_user_aes(username)
    if not user_rsa:
        return jsonify({"error": f"RSA key for {username} not found"}), 400
    return jsonify({"rsa": user_rsa})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)