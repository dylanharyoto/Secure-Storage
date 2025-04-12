import os

# Default database directory
DB_DIR = os.getenv('DB_DIR', os.path.join(os.path.dirname(__file__), 'Database'))

# Server port
SERVER_PORT = int(os.getenv('SERVER_PORT', '5100'))

# Admin credentials
ADMIN_USER = os.getenv('ADMIN_USER', 'dylanharyoto.polyu@gmail.com')

# Database table names (used as keys in Flask app.config)
USERS_DB = "USERS_DB"
FILES_DB = "FILES_DB"
OTPS_DB = "OTPS_DB"
PENDINGS_DB = "PENDINGS_DB"
LOGS_DB = "LOGS_DB"