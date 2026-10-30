"""Reset the super-administrator password.  Usage:  python reset_admin.py

Uses the same storage as the server: Supabase/PostgreSQL if DATABASE_URL is set, otherwise local SQLite.
Tip: if BFE_ADMIN_PASSWORD is set in .env, the server re-applies that value on start-up, so change it there.
"""
import getpass
import sys

from werkzeug.security import generate_password_hash

import config
from app import open_storage

username = config.SUPER_ADMIN
password = getpass.getpass(f"New password for '{username}' (min {config.MIN_PASSWORD_LENGTH} chars): ")
if len(password) < config.MIN_PASSWORD_LENGTH:
    sys.exit("Password too short.")
keys, db = open_storage()
pw_hash = generate_password_hash(password, method="scrypt")
if db.get_operator(username):
    db.set_operator_password(username, pw_hash)
else:
    db.create_operator(username, pw_hash, "admin")
db.audit("console", "reset_password", "ok", target=username)
db.close()
print(f"Password for '{username}' updated. You can sign in now.")
