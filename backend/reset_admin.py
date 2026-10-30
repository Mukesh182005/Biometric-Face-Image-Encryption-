"""Reset the super-administrator password.  Usage:  python reset_admin.py"""
import getpass
import sys

from werkzeug.security import generate_password_hash

import config
from crypto_engine import KeyManager
from database import Database

username = config.SUPER_ADMIN
password = getpass.getpass(f"New password for '{username}' (min {config.MIN_PASSWORD_LENGTH} chars): ")
if len(password) < config.MIN_PASSWORD_LENGTH:
    sys.exit("Password too short.")
keys = KeyManager(config.KEYRING_PATH, config.MASTER_PASSPHRASE)
db = Database(config.DB_PATH, keys.audit_key)
pw_hash = generate_password_hash(password, method="scrypt")
if db.get_operator(username):
    with db.connect() as c:
        c.execute("UPDATE operators SET password_hash = ?, failed_attempts = 0, locked_until = NULL "
                  "WHERE username = ?", (pw_hash, username))
else:
    db.create_operator(username, pw_hash, "admin")
db.audit("console", "reset_password", "ok", target=username)
print(f"Password for '{username}' updated. You can sign in now.")
