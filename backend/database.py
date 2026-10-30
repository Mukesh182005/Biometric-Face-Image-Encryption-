"""
Persistence layer. Only ciphertext, nonces, wrapped keys and HMACs are stored.

Two backends, same queries:
  * SQLite (a file under backend/instance)  - local use, start.bat
  * PostgreSQL via DATABASE_URL (Supabase)  - hosts without a persistent disk, e.g. Render's free plan.
    Tables live in a private `facevault` schema, which Supabase does not expose through its REST API.
"""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

from crypto_engine import GENESIS, audit_entry_mac, utcnow_iso

SQLITE_SCHEMA = """
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

-- Small encrypted values: the RSA transport key (and the keyring, in PostgreSQL mode).
CREATE TABLE IF NOT EXISTS blobs (
    name        TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
"""

PG_SCHEMA_NAME = "facevault"
PG_SCHEMA = [
    f"CREATE SCHEMA IF NOT EXISTS {PG_SCHEMA_NAME}",
    f"SET search_path TO {PG_SCHEMA_NAME}",
    """CREATE TABLE IF NOT EXISTS operators (
        id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        username        TEXT UNIQUE NOT NULL,
        password_hash   TEXT NOT NULL,
        role            TEXT NOT NULL CHECK (role IN ('admin', 'operator')),
        failed_attempts INTEGER NOT NULL DEFAULT 0,
        locked_until    DOUBLE PRECISION,
        created_at      TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS subjects (
        id              TEXT PRIMARY KEY,
        email_index     TEXT UNIQUE NOT NULL,
        template_ct     BYTEA NOT NULL,
        template_nonce  BYTEA NOT NULL,
        pii_ct          BYTEA NOT NULL,
        pii_nonce       BYTEA NOT NULL,
        wrapped_dek     BYTEA NOT NULL,
        key_version     INTEGER NOT NULL,
        samples         INTEGER NOT NULL,
        created_at      TEXT NOT NULL,
        created_by      TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS audit_log (
        id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        ts          TEXT NOT NULL,
        actor       TEXT NOT NULL,
        action      TEXT NOT NULL,
        target      TEXT,
        ip          TEXT,
        outcome     TEXT NOT NULL,
        details     TEXT,
        prev_mac    TEXT NOT NULL,
        entry_mac   TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS blobs (
        name        TEXT PRIMARY KEY,
        value       TEXT NOT NULL,
        updated_at  TEXT NOT NULL)""",
    # Defence in depth on Supabase: even if the schema were ever exposed through the REST API,
    # row-level security with no policies denies every anon/authenticated request.
    *[f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY" for t in ("operators", "subjects", "audit_log", "blobs")],
]
AUDIT_LOCK_ID = 7_315_204  # pg_advisory_xact_lock key: one audit append at a time, across processes


def is_postgres_url(target) -> bool:
    return isinstance(target, str) and target.startswith(("postgres://", "postgresql://"))


class _PgConnection:
    """Gives a psycopg connection the sqlite3-style `?` placeholders the queries are written with."""

    def __init__(self, conn):
        self._conn = conn

    def execute(self, sql: str, params=()):
        return self._conn.execute(sql.replace("?", "%s"), params)


class Database:
    def __init__(self, target: Path | str, audit_key: bytes | None = None):
        self.audit_key = audit_key  # set after the keyring is unlocked (the keyring may live in this DB)
        self._audit_lock = threading.Lock()
        self.is_postgres = is_postgres_url(target)
        if self.is_postgres:
            from psycopg.rows import dict_row
            from psycopg_pool import ConnectionPool

            def configure(conn):
                conn.execute(f"SET search_path TO {PG_SCHEMA_NAME}")
                conn.commit()

            # prepare_threshold=None: no server-side prepared statements, so Supabase's poolers work.
            self._pool = ConnectionPool(
                target, min_size=1, max_size=4, open=True, configure=configure, timeout=30,
                kwargs={"row_factory": dict_row, "prepare_threshold": None})
            with self.connect() as c:
                for stmt in PG_SCHEMA:
                    c.execute(stmt)
        else:
            self.path = Path(target)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.connect() as conn:
                conn.executescript(SQLITE_SCHEMA)

    @property
    def backend(self) -> str:
        return "postgresql" if self.is_postgres else "sqlite"

    @contextmanager
    def connect(self):
        """One transaction: commits on success, rolls back on error, always releases the connection."""
        if self.is_postgres:
            with self._pool.connection() as conn:
                yield _PgConnection(conn)
            return
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

    def close(self) -> None:
        if self.is_postgres:
            self._pool.close()

    # -- blobs (encrypted keyring / transport key) --------------------------- #
    def get_blob(self, name: str) -> str | None:
        with self.connect() as c:
            row = c.execute("SELECT value FROM blobs WHERE name = ?", (name,)).fetchone()
            return row["value"] if row else None

    def put_blob(self, name: str, value: str) -> None:
        with self.connect() as c:
            c.execute("INSERT INTO blobs (name, value, updated_at) VALUES (?, ?, ?) "
                      "ON CONFLICT (name) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                      (name, value, utcnow_iso()))

    # -- operators --------------------------------------------------------- #
    def get_operator(self, username: str):
        with self.connect() as c:
            return c.execute("SELECT * FROM operators WHERE username = ?", (username,)).fetchone()

    def count_operators(self) -> int:
        with self.connect() as c:
            return c.execute("SELECT COUNT(*) AS n FROM operators").fetchone()["n"]

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
            rows = c.execute("SELECT key_version, COUNT(*) AS n FROM subjects GROUP BY key_version").fetchall()
            return {r["key_version"]: r["n"] for r in rows}

    # -- audit chain ------------------------------------------------------- #
    def audit(self, actor: str, action: str, outcome: str, target: str | None = None,
              ip: str | None = None, details: str | None = None) -> None:
        with self._audit_lock, self.connect() as c:
            if self.is_postgres:
                # Serialise appends across processes too, so two writers can't fork the HMAC chain.
                c.execute("SELECT pg_advisory_xact_lock(?)", (AUDIT_LOCK_ID,))
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
            for row in c.execute("SELECT * FROM audit_log ORDER BY id").fetchall():
                entry = {k: row[k] for k in ("ts", "actor", "action", "target", "ip", "outcome", "details")}
                expected = audit_entry_mac(self.audit_key, prev, entry)
                if row["prev_mac"] != prev or row["entry_mac"] != expected:
                    return {"valid": False, "checked": count, "broken_at": row["id"]}
                prev = row["entry_mac"]
                count += 1
        return {"valid": True, "checked": count, "head": prev}

    def stats(self) -> dict:
        def count(c, sql: str) -> int:
            return c.execute(sql).fetchone()["n"]

        with self.connect() as c:
            return {
                "subjects": count(c, "SELECT COUNT(*) AS n FROM subjects"),
                "operators": count(c, "SELECT COUNT(*) AS n FROM operators"),
                "audit_entries": count(c, "SELECT COUNT(*) AS n FROM audit_log"),
                "verifications_ok": count(
                    c, "SELECT COUNT(*) AS n FROM audit_log WHERE action='verify' AND outcome='match'"),
                "verifications_fail": count(
                    c, "SELECT COUNT(*) AS n FROM audit_log WHERE action='verify' AND outcome!='match'"),
            }
