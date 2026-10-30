"""
Cryptographic core of the Biometric Face Encryption system.

Three independent protection layers:

1. TRANSPORT  (client -> server)
   Hybrid encryption: the browser generates a fresh AES-256-GCM key, encrypts the
   face descriptor with it, and wraps that key with the server's RSA-3072-OAEP
   (SHA-256) public key. A timestamp + random nonce inside the ciphertext give
   replay protection. This runs *inside* TLS (defence in depth).

2. STORAGE  (data at rest)
   Envelope encryption: every subject record gets its own random Data Encryption
   Key (DEK). The DEK encrypts the 128-float template and the PII with
   AES-256-GCM. The DEK itself is wrapped by a Key Encryption Key (KEK) taken from
   a versioned keyring. Associated data (AAD) binds each ciphertext to its record
   id, so ciphertexts cannot be swapped between rows.

3. INTEGRITY  (audit trail + lookups)
   * HMAC-SHA256 blind index of the e-mail address allows lookups without storing
     the e-mail in plaintext.
   * HMAC-SHA256 hash chain over the audit log makes tampering detectable.

The keyring file is itself encrypted with a key derived from a passphrase via
scrypt (memory-hard KDF) and AES-256-GCM.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import struct
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

DESCRIPTOR_DIM = 128
TRANSPORT_AAD = b"bfe-transport-v1"


class CryptoError(Exception):
    """Raised for any decryption / integrity failure. Message is safe to show."""


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    try:
        return base64.b64decode(data, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise CryptoError("Malformed base64 data") from exc


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
#  Feature vector serialisation / validation
# --------------------------------------------------------------------------- #
def validate_descriptor(values) -> list[float]:
    if not isinstance(values, list) or len(values) != DESCRIPTOR_DIM:
        raise CryptoError(f"Descriptor must be a list of {DESCRIPTOR_DIM} numbers")
    out = []
    for v in values:
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            raise CryptoError("Descriptor contains non-numeric values")
        f = float(v)
        if not math.isfinite(f) or abs(f) > 10:
            raise CryptoError("Descriptor contains out-of-range values")
        out.append(f)
    return out


def pack_vector(values: list[float]) -> bytes:
    """128 x float32 little-endian = 512 bytes."""
    return struct.pack(f"<{DESCRIPTOR_DIM}f", *values)


def unpack_vector(blob: bytes) -> list[float]:
    if len(blob) != DESCRIPTOR_DIM * 4:
        raise CryptoError("Decrypted template has wrong length")
    return list(struct.unpack(f"<{DESCRIPTOR_DIM}f", blob))


def euclidean_distance(a: list[float], b: list[float]) -> float:
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))


# --------------------------------------------------------------------------- #
#  Key management
# --------------------------------------------------------------------------- #
class FileBlob:
    """Stores one text value in a file (local / single-server deployments)."""

    def __init__(self, path: Path):
        self.path = Path(path)

    def read(self) -> str | None:
        return self.path.read_text() if self.path.exists() else None

    def write(self, text: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(text)
        os.replace(tmp, self.path)


class DbBlob:
    """Stores one text value in the database's `blobs` table (hosts without a persistent disk)."""

    def __init__(self, db, name: str):
        self.db, self.name = db, name

    def read(self) -> str | None:
        return self.db.get_blob(self.name)

    def write(self, text: str) -> None:
        self.db.put_blob(self.name, text)


class KeyManager:
    """
    Versioned keyring, encrypted with a passphrase-derived key and persisted to a file or the database.

    Contents:
      kek_roots   : {version: 32 random bytes}  -> HKDF -> KEK used to wrap DEKs
      active      : currently active KEK version (new records use it)
      index_key   : HMAC key for blind indexes
      audit_key   : HMAC key for the audit hash chain
      jwt_secret  : HMAC key for signing session tokens
    """

    SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 1

    def __init__(self, store: Path | str | FileBlob | DbBlob, passphrase: str):
        self.store = store if isinstance(store, (FileBlob, DbBlob)) else FileBlob(Path(store))
        self._passphrase = passphrase.encode("utf-8")
        self._lock = threading.Lock()
        raw = self.store.read()
        if raw:
            self._ring = self._load(raw)
        else:
            self._ring = self._new_ring()
            self._save()

    # -- persistence ------------------------------------------------------- #
    def _derive_file_key(self, salt: bytes) -> bytes:
        return Scrypt(salt=salt, length=32, n=self.SCRYPT_N, r=self.SCRYPT_R,
                      p=self.SCRYPT_P).derive(self._passphrase)

    @staticmethod
    def _new_ring() -> dict:
        return {
            "active": 1,
            "kek_roots": {"1": {"key": b64e(os.urandom(32)), "created": utcnow_iso()}},
            "index_key": b64e(os.urandom(32)),
            "audit_key": b64e(os.urandom(32)),
            "jwt_secret": b64e(os.urandom(32)),
        }

    def _save(self) -> None:
        salt, nonce = os.urandom(16), os.urandom(12)
        key = self._derive_file_key(salt)
        ct = AESGCM(key).encrypt(nonce, json.dumps(self._ring).encode(), b"bfe-keyring")
        blob = {
            "format": "bfe-keyring-v1",
            "kdf": {"name": "scrypt", "n": self.SCRYPT_N, "r": self.SCRYPT_R,
                    "p": self.SCRYPT_P, "salt": b64e(salt)},
            "cipher": "AES-256-GCM",
            "nonce": b64e(nonce),
            "ciphertext": b64e(ct),
        }
        self.store.write(json.dumps(blob, indent=2))

    def _load(self, raw: str) -> dict:
        blob = json.loads(raw)
        key = self._derive_file_key(b64d(blob["kdf"]["salt"]))
        try:
            pt = AESGCM(key).decrypt(b64d(blob["nonce"]), b64d(blob["ciphertext"]), b"bfe-keyring")
        except InvalidTag as exc:
            raise CryptoError("Cannot unlock keyring: wrong passphrase or corrupted file") from exc
        return json.loads(pt)

    # -- accessors --------------------------------------------------------- #
    @property
    def active_version(self) -> int:
        return int(self._ring["active"])

    def versions(self) -> list[dict]:
        return [{"version": int(v), "created": meta["created"],
                 "active": int(v) == self.active_version}
                for v, meta in sorted(self._ring["kek_roots"].items(), key=lambda kv: int(kv[0]))]

    def kek(self, version: int) -> bytes:
        meta = self._ring["kek_roots"].get(str(version))
        if meta is None:
            raise CryptoError(f"Unknown key version {version}")
        # HKDF gives key separation: the root is never used directly for encryption.
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=f"bfe/kek-wrap/v{version}".encode()).derive(b64d(meta["key"]))

    @property
    def index_key(self) -> bytes:
        return b64d(self._ring["index_key"])

    @property
    def audit_key(self) -> bytes:
        return b64d(self._ring["audit_key"])

    @property
    def jwt_secret(self) -> bytes:
        return b64d(self._ring["jwt_secret"])

    def change_passphrase(self, new_passphrase: str) -> None:
        """Re-encrypt the keyring file under a new passphrase (fresh salt and nonce). Keys are unchanged."""
        with self._lock:
            self._passphrase = new_passphrase.encode("utf-8")
            self._save()

    def rotate(self) -> int:
        """Create a new KEK version and make it active. Old versions stay for unwrapping."""
        with self._lock:
            new_v = max(int(v) for v in self._ring["kek_roots"]) + 1
            self._ring["kek_roots"][str(new_v)] = {"key": b64e(os.urandom(32)), "created": utcnow_iso()}
            self._ring["active"] = new_v
            self._save()
            return new_v

    def retire(self, version: int) -> None:
        """Delete an old KEK once no record uses it any more (crypto-shredding)."""
        with self._lock:
            if version == self.active_version:
                raise CryptoError("Cannot retire the active key")
            self._ring["kek_roots"].pop(str(version), None)
            self._save()


# --------------------------------------------------------------------------- #
#  Storage encryption (envelope encryption)
# --------------------------------------------------------------------------- #
class TemplateCipher:
    def __init__(self, keys: KeyManager):
        self.keys = keys

    @staticmethod
    def _aad(kind: str, record_id: str) -> bytes:
        return f"bfe:{kind}:v1:{record_id}".encode()

    def _wrap_dek(self, record_id: str, dek: bytes, version: int) -> bytes:
        nonce = os.urandom(12)
        aad = f"bfe:dek:{record_id}:{version}".encode()
        return nonce + AESGCM(self.keys.kek(version)).encrypt(nonce, dek, aad)

    def _unwrap_dek(self, record_id: str, wrapped: bytes, version: int) -> bytes:
        aad = f"bfe:dek:{record_id}:{version}".encode()
        try:
            return AESGCM(self.keys.kek(version)).decrypt(wrapped[:12], wrapped[12:], aad)
        except InvalidTag as exc:
            raise CryptoError("DEK unwrap failed (tampered record or wrong key)") from exc

    def seal(self, record_id: str, vector: list[float], pii: dict) -> dict:
        dek = AESGCM.generate_key(bit_length=256)
        aes = AESGCM(dek)
        t_nonce, p_nonce = os.urandom(12), os.urandom(12)
        template_ct = aes.encrypt(t_nonce, pack_vector(vector), self._aad("template", record_id))
        pii_ct = aes.encrypt(p_nonce, json.dumps(pii).encode(), self._aad("pii", record_id))
        version = self.keys.active_version
        return {
            "template_ct": template_ct,
            "template_nonce": t_nonce,
            "pii_ct": pii_ct,
            "pii_nonce": p_nonce,
            "wrapped_dek": self._wrap_dek(record_id, dek, version),
            "key_version": version,
        }

    def _open(self, row, kind: str) -> bytes:
        dek = self._unwrap_dek(row["id"], row["wrapped_dek"], row["key_version"])
        ct, nonce = row[f"{kind}_ct"], row[f"{kind}_nonce"]
        try:
            return AESGCM(dek).decrypt(nonce, ct, self._aad(kind, row["id"]))
        except InvalidTag as exc:
            raise CryptoError(f"{kind} authentication failed (record was tampered with)") from exc

    def open_template(self, row) -> list[float]:
        return unpack_vector(self._open(row, "template"))

    def open_pii(self, row) -> dict:
        return json.loads(self._open(row, "pii"))

    def rewrap(self, row) -> tuple[bytes, int]:
        """Re-wrap a record's DEK under the active KEK. The bulk data is untouched."""
        dek = self._unwrap_dek(row["id"], row["wrapped_dek"], row["key_version"])
        version = self.keys.active_version
        return self._wrap_dek(row["id"], dek, version), version


def blind_index(key: bytes, value: str) -> str:
    """Deterministic keyed hash for equality lookups on encrypted fields."""
    return hmac.new(key, value.strip().lower().encode(), hashlib.sha256).hexdigest()


# --------------------------------------------------------------------------- #
#  Transport encryption (client -> server hybrid RSA-OAEP + AES-GCM)
# --------------------------------------------------------------------------- #
class TransportCipher:
    """
    The RSA private key can be persisted (encrypted with the master passphrase) so that it survives
    restarts: on hosts that sleep when idle, a browser that fetched the public key before the restart
    would otherwise send envelopes the new process cannot open.
    """

    def __init__(self, max_skew_seconds: int = 120, private_key_pem: bytes | None = None,
                 passphrase: str | None = None):
        self._private = None
        if private_key_pem:
            try:
                self._private = serialization.load_pem_private_key(
                    private_key_pem, password=passphrase.encode() if passphrase else None)
            except (ValueError, TypeError):
                self._private = None  # stored under an old passphrase: replace it with a fresh key
        self.generated = self._private is None
        if self._private is None:
            self._private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        self.max_skew = max_skew_seconds
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()
        spki = self._private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.public_spki_b64 = b64e(spki)
        self.fingerprint = hashlib.sha256(spki).hexdigest()

    def _check_replay(self, nonce: str, ts_ms: int) -> None:
        now = time.time()
        if abs(now - ts_ms / 1000) > self.max_skew:
            raise CryptoError("Envelope expired or clock skew too large")
        with self._lock:
            for k in [k for k, exp in self._seen.items() if exp < now]:
                del self._seen[k]
            if nonce in self._seen:
                raise CryptoError("Replay detected: envelope already used")
            self._seen[nonce] = now + self.max_skew * 2

    def decrypt(self, envelope: dict) -> dict:
        if not isinstance(envelope, dict) or envelope.get("alg") != "RSA-OAEP-256+A256GCM":
            raise CryptoError("Unsupported or missing transport envelope")
        try:
            aes_key = self._private.decrypt(
                b64d(envelope["ek"]),
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            plaintext = AESGCM(aes_key).decrypt(b64d(envelope["iv"]), b64d(envelope["ct"]), TRANSPORT_AAD)
            payload = json.loads(plaintext)
        except (KeyError, ValueError, InvalidTag, TypeError) as exc:
            raise CryptoError("Transport envelope could not be decrypted") from exc
        nonce, ts = payload.get("nonce"), payload.get("ts")
        if not isinstance(nonce, str) or len(nonce) < 16 or not isinstance(ts, (int, float)):
            raise CryptoError("Envelope missing freshness fields")
        self._check_replay(nonce, int(ts))
        return payload

    def export_pem(self, passphrase: str) -> bytes:
        """Private key as PKCS#8 PEM, encrypted under the master passphrase."""
        return self._private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(passphrase.encode()))

    def public_key_object(self):
        return self._private.public_key()


# --------------------------------------------------------------------------- #
#  Tamper-evident audit chain
# --------------------------------------------------------------------------- #
GENESIS = "0" * 64


def audit_entry_mac(key: bytes, prev_mac: str, entry: dict) -> str:
    canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    return hmac.new(key, (prev_mac + canonical).encode(), hashlib.sha256).hexdigest()
