import sqlite3
from SourceCode.shared.utils import generate_aes, hash_password, split_aes

def init_conn(db_filename):
    conn = sqlite3.connect(db_filename)
    cursor = conn.cursor()
    return (conn, cursor)

def register_user(username, password):
    hashed_password = hash_password(password)
    client_aes, server_aes = split_aes(generate_aes())

