# Secure-Storage

1. Open Terminal
2. Split Terminal
3. Run "python3 client.py" on one of the Terminal(s).
4. Run "python3 server.py" on the other Terminal.

init_database() is a function to initialize a .db file. The reason why it is in utils is, client may need that to make a db to store half of the AES key.

When you boot up the server (run), the users.db will be created under /server/data, if not exist yet.

Then, you can just interact with the client to register your username (email) and password.
