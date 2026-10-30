"""
Re-encrypt the keyring under a new master passphrase without losing any data.

Usage:  python change_passphrase.py
Works for both storage modes (local keyring.enc, or the keyring row in Supabase/PostgreSQL when
DATABASE_URL is set). It unlocks the keyring with the current BFE_MASTER_PASSPHRASE, asks for the new
one, keeps a backup copy, re-encrypts, and verifies. Afterwards put the new value in .env (and in your
host's environment settings). The RSA transport key is regenerated automatically on the next start.
"""
import getpass
import sys

import config
from app import open_storage
from crypto_engine import CryptoError, DbBlob, FileBlob, KeyManager

try:
    keys, db = open_storage()
except CryptoError:
    old = getpass.getpass("Current passphrase (the configured one did not unlock the keyring): ")
    keys, db = open_storage(passphrase=old)

new = getpass.getpass("New passphrase (16+ characters): ")
if len(new) < 16:
    sys.exit("Passphrase too short.")
if getpass.getpass("Repeat new passphrase: ") != new:
    sys.exit("Passphrases do not match.")

backup = DbBlob(db, "keyring.bak") if db.is_postgres else FileBlob(config.KEYRING_PATH.with_suffix(".enc.bak"))
backup.write(keys.store.read())
keys.change_passphrase(new)
KeyManager(keys.store, new)  # raises if the new passphrase does not unlock it
db.close()
where = "the database (blob 'keyring.bak')" if db.is_postgres else str(backup.path)
print(f"Keyring re-encrypted. Old copy kept in {where}.")
print("Now set BFE_MASTER_PASSPHRASE to the new value.")
