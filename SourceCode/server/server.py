from flask import Flask, request, jsonify, g
import sqlite3
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from SourceCode.shared.utils import generate_aes, hash_password, split_aes, init_database, check_password  # Import check_password

# Initialize Flask app
app = Flask(__name__)
app.config['DATABASE'] = os.path.join(os.path.dirname(__file__), "data", "users.db")

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

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    server_aes = data.get('key')
    db = get_db()
    cursor = db.cursor()
    hashed_password = hash_password(password)
    cursor.execute(
        "INSERT INTO users (username, password, key) VALUES (?, ?, ?)",
        (username, hashed_password, server_aes)
    )
    db.commit()
    return jsonify({"message": "Registered Successfully"}), 200

@app.route('/login', methods=['POST'])
def login():
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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5200, debug=True)