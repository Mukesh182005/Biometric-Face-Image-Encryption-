"""SQLite persistence layer. Only ciphertext, nonces, wrapped keys and HMACs are stored."""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

from crypto_engine import GENESIS, audit_entry_mac, utcnow_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS operators (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,              -- scrypt (salted, memory-hard)
    role            TEXT NOT NULL CHECK (role IN ('admin', 'operator')),
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    REAL,
    created_at      TEXT NOT NULL
);

-- One row per enrolled person. NOTHING here is readable without the keyring.
CREATE TABLE IF NOT EXISTS subjects (
    id              TEXT PRIMARY KEY,           -- random UUID, also bound into AAD
    email_index     TEXT UNIQUE NOT NULL,       -- HMAC-SHA256 blind index
    template_ct     BLOB NOT NULL,              -- AES-256-GCM(512-byte float32 vector) + tag
    template_nonce  BLOB NOT NULL,              -- 96-bit GCM nonce
    pii_ct          BLOB NOT NULL,              -- AES-256-GCM({name, email})
    pii_nonce       BLOB NOT NULL,
    wrapped_dek     BLOB NOT NULL,              -- nonce || AES-GCM(KEK_v, DEK)
    key_version     INTEGER NOT NULL,           -- which KEK wrapped the DEK
    samples         INTEGER NOT NULL,
    created_at      TEXT NOT NULL,
    created_by      TEXT NOT NULL
);

-- Append-only audit trail, each entry chained to the previous by HMAC.
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    target      TEXT,
    ip          TEXT,
    outcome     TEXT NOT NULL,
    details     TEXT,
    prev_mac    TEXT NOT NULL,
    entry_mac   TEXT NOT NULL
);
"""


class Database:
    def __init__(self, path: Path, audit_key: bytes):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.audit_key = audit_key
        self._audit_lock = threading.Lock()
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def connect(self):
        """Short-lived connection: commits on success, rolls back on error, always closes."""
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA secure_delete=ON")  # overwrite deleted content with zeros
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    # -- operators --------------------------------------------------------- #
    def get_operator(self, username: str):
        with self.connect() as c:
            return c.execute("SELECT * FROM operators WHERE username = ?", (username,)).fetchone()

    def count_operators(self) -> int:
        with self.connect() as c:
            return c.execute("SELECT COUNT(*) FROM operators").fetchone()[0]

    def list_operators(self):
        with self.connect() as c:
            return c.execute("SELECT id, username, role, created_at, locked_until FROM operators "
                             "ORDER BY id").fetchall()

    def create_operator(self, username: str, password_hash: str, role: str) -> None:
        with self.connect() as c:
            c.execute("INSERT INTO operators (username, password_hash, role, created_at) "
                      "VALUES (?, ?, ?, ?)", (username, password_hash, role, utcnow_iso()))

    def set_operator_password(self, username: str, password_hash: str) -> None:
        """Replace the password hash and clear any lockout."""
        with self.connect() as c:
            c.execute("UPDATE operators SET password_hash = ?, failed_attempts = 0, locked_until = NULL "
                      "WHERE username = ?", (password_hash, username))

    def record_login_failure(self, username: str, max_attempts: int, lock_seconds: int, now: float):
        with self.connect() as c:
            c.execute("UPDATE operators SET failed_attempts = failed_attempts + 1 WHERE username = ?",
                      (username,))
            c.execute("UPDATE operators SET locked_until = ?, failed_attempts = 0 "
                      "WHERE username = ? AND failed_attempts >= ?",
                      (now + lock_seconds, username, max_attempts))

    def record_login_success(self, username: str):
        with self.connect() as c:
            c.execute("UPDATE operators SET failed_attempts = 0, locked_until = NULL WHERE username = ?",
                      (username,))

    # -- subjects ---------------------------------------------------------- #
    def insert_subject(self, record_id: str, email_index: str, sealed: dict, samples: int, actor: str):
        with self.connect() as c:
            c.execute(
                "INSERT INTO subjects (id, email_index, template_ct, template_nonce, pii_ct, pii_nonce, "
                "wrapped_dek, key_version, samples, created_at, created_by) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (record_id, email_index, sealed["template_ct"], sealed["template_nonce"],
                 sealed["pii_ct"], sealed["pii_nonce"], sealed["wrapped_dek"],
                 sealed["key_version"], samples, utcnow_iso(), actor))

    def get_subject_by_index(self, email_index: str):
        with self.connect() as c:
            return c.execute("SELECT * FROM subjects WHERE email_index = ?", (email_index,)).fetchone()

    def get_subject(self, record_id: str):
        with self.connect() as c:
            return c.execute("SELECT * FROM subjects WHERE id = ?", (record_id,)).fetchone()

    def all_subjects(self):
        with self.connect() as c:
            return c.execute("SELECT * FROM subjects ORDER BY created_at DESC").fetchall()

    def delete_subject(self, record_id: str) -> bool:
        with self.connect() as c:
            return c.execute("DELETE FROM subjects WHERE id = ?", (record_id,)).rowcount > 0

    def update_wrapped_dek(self, record_id: str, wrapped: bytes, version: int):
        with self.connect() as c:
            c.execute("UPDATE subjects SET wrapped_dek = ?, key_version = ? WHERE id = ?",
                      (wrapped, version, record_id))

    def key_version_usage(self) -> dict[int, int]:
        with self.connect() as c:
            rows = c.execute("SELECT key_version, COUNT(*) n FROM subjects GROUP BY key_version").fetchall()
            return {r["key_version"]: r["n"] for r in rows}

    # -- audit chain ------------------------------------------------------- #
    def audit(self, actor: str, action: str, outcome: str, target: str | None = None,
              ip: str | None = None, details: str | None = None) -> None:
        with self._audit_lock, self.connect() as c:
            last = c.execute("SELECT entry_mac FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
            prev = last["entry_mac"] if last else GENESIS
            entry = {"ts": utcnow_iso(), "actor": actor, "action": action, "target": target,
                     "ip": ip, "outcome": outcome, "details": details}
            mac = audit_entry_mac(self.audit_key, prev, entry)
            c.execute("INSERT INTO audit_log (ts, actor, action, target, ip, outcome, details, "
                      "prev_mac, entry_mac) VALUES (?,?,?,?,?,?,?,?,?)",
                      (entry["ts"], actor, action, target, ip, outcome, details, prev, mac))

    def audit_entries(self, limit: int = 200):
        with self.connect() as c:
            return c.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def verify_audit_chain(self) -> dict:
        prev = GENESIS
        count = 0
        with self.connect() as c:
            for row in c.execute("SELECT * FROM audit_log ORDER BY id"):
                entry = {k: row[k] for k in ("ts", "actor", "action", "target", "ip", "outcome", "details")}
                expected = audit_entry_mac(self.audit_key, prev, entry)
                if row["prev_mac"] != prev or row["entry_mac"] != expected:
                    return {"valid": False, "checked": count, "broken_at": row["id"]}
                prev = row["entry_mac"]
                count += 1
        return {"valid": True, "checked": count, "head": prev}

    def stats(self) -> dict:
        with self.connect() as c:
            return {
                "subjects": c.execute("SELECT COUNT(*) FROM subjects").fetchone()[0],
                "operators": c.execute("SELECT COUNT(*) FROM operators").fetchone()[0],
                "audit_entries": c.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0],
                "verifications_ok": c.execute(
                    "SELECT COUNT(*) FROM audit_log WHERE action='verify' AND outcome='match'").fetchone()[0],
                "verifications_fail": c.execute(
                    "SELECT COUNT(*) FROM audit_log WHERE action='verify' AND outcome!='match'").fetchone()[0],
            }
