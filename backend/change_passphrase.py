"""
Re-encrypt the keyring under a new master passphrase without losing any data.

Usage:  python change_passphrase.py
It unlocks keyring.enc with the current passphrase (BFE_MASTER_PASSPHRASE from .env, or the dev
default), asks for the new one, re-encrypts, then verifies the new passphrase works. Afterwards put
the new value in .env as BFE_MASTER_PASSPHRASE. A backup of the old keyring is kept next to it.
"""
import getpass
import shutil
import sys

import config
from crypto_engine import CryptoError, KeyManager

if not config.KEYRING_PATH.exists():
    sys.exit(f"No keyring at {config.KEYRING_PATH}. Just set BFE_MASTER_PASSPHRASE in .env and start the app.")

try:
    keys = KeyManager(config.KEYRING_PATH, config.MASTER_PASSPHRASE)
except CryptoError:
    old = getpass.getpass("Current passphrase (the one in .env did not unlock the keyring): ")
    keys = KeyManager(config.KEYRING_PATH, old)

new = getpass.getpass("New passphrase (16+ characters): ")
if len(new) < 16:
    sys.exit("Passphrase too short.")
if getpass.getpass("Repeat new passphrase: ") != new:
    sys.exit("Passphrases do not match.")

backup = config.KEYRING_PATH.with_suffix(".enc.bak")
shutil.copy2(config.KEYRING_PATH, backup)
keys.change_passphrase(new)
KeyManager(config.KEYRING_PATH, new)  # raises if the new passphrase does not unlock it
print(f"Keyring re-encrypted. Old copy kept at {backup}.\nNow set BFE_MASTER_PASSPHRASE to the new value in .env.")
