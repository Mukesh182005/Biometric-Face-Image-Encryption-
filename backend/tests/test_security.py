"""
Security test-suite. Run from the backend folder:  python -m unittest discover -v tests
"""
import base64
import json
import os
import random
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

from app import create_app  # noqa: E402
from crypto_engine import (TRANSPORT_AAD, CryptoError, KeyManager, TemplateCipher,  # noqa: E402
                           TransportCipher, blind_index, euclidean_distance)
from database import Database  # noqa: E402

ADMIN_PW = "Admin-password-123"
SUPER = "mukeshrao1704@gmail.com"


def rand_vec(seed: int) -> list[float]:
    rng = random.Random(seed)
    return [rng.uniform(-0.2, 0.2) for _ in range(128)]


def noisy(vec, seed, scale=0.01):
    rng = random.Random(seed)
    return [v + rng.uniform(-scale, scale) for v in vec]


def client_envelope(transport: TransportCipher, payload: dict, ts=None, nonce=None) -> dict:
    """Python re-implementation of the browser's sealForTransport()."""
    body = dict(payload, ts=ts if ts is not None else int(time.time() * 1000),
                nonce=nonce or os.urandom(16).hex())
    key, iv = AESGCM.generate_key(256), os.urandom(12)
    ct = AESGCM(key).encrypt(iv, json.dumps(body).encode(), TRANSPORT_AAD)
    ek = transport.public_key_object().encrypt(
        key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    b = lambda x: base64.b64encode(x).decode()  # noqa: E731
    return {"v": 1, "alg": "RSA-OAEP-256+A256GCM", "ek": b(ek), "iv": b(iv), "ct": b(ct)}


class CryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.keys = KeyManager(Path(cls.tmp.name) / "ring.enc", "test-passphrase")
        cls.cipher = TemplateCipher(cls.keys)
        cls.transport = TransportCipher(120)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def sealed_row(self, rid="rec-1", vec=None):
        sealed = self.cipher.seal(rid, vec or rand_vec(1), {"name": "Alice", "email": "a@x.io"})
        return dict(id=rid, **sealed)

    def test_roundtrip(self):
        vec = rand_vec(7)
        row = self.sealed_row(vec=vec)
        out = self.cipher.open_template(row)
        self.assertLess(max(abs(a - b) for a, b in zip(vec, out)), 1e-6)
        self.assertEqual(self.cipher.open_pii(row)["name"], "Alice")

    def test_ciphertext_hides_plaintext_and_is_randomised(self):
        vec = rand_vec(3)
        a, b = self.sealed_row(vec=vec), self.sealed_row(vec=vec)
        self.assertNotEqual(a["template_ct"], b["template_ct"])  # fresh DEK + nonce each time
        self.assertEqual(len(a["template_ct"]), 512 + 16)        # data + 128-bit GCM tag
        self.assertNotIn(b"Alice", a["pii_ct"])

    def test_bit_flip_detected(self):
        row = self.sealed_row()
        ct = bytearray(row["template_ct"])
        ct[100] ^= 0x80
        row["template_ct"] = bytes(ct)
        with self.assertRaises(CryptoError):
            self.cipher.open_template(row)

    def test_row_swap_detected(self):
        row = self.sealed_row("rec-A")
        row["id"] = "rec-B"  # attacker copies ciphertext onto another identity
        with self.assertRaises(CryptoError):
            self.cipher.open_template(row)

    def test_key_rotation_rewraps(self):
        row = self.sealed_row("rot")
        old_v = row["key_version"]
        new_v = self.keys.rotate()
        row["wrapped_dek"], row["key_version"] = self.cipher.rewrap(row)
        self.assertEqual(row["key_version"], new_v)
        self.assertNotEqual(old_v, new_v)
        self.cipher.open_template(row)
        self.keys.retire(old_v)  # crypto-shredding of old key
        with self.assertRaises(CryptoError):
            self.keys.kek(old_v)

    def test_keyring_wrong_passphrase(self):
        with self.assertRaises(CryptoError):
            KeyManager(Path(self.tmp.name) / "ring.enc", "wrong")

    def test_keyring_file_has_no_plain_keys(self):
        raw = (Path(self.tmp.name) / "ring.enc").read_text()
        self.assertNotIn(self.keys._ring["index_key"], raw)

    def test_blind_index(self):
        k = self.keys.index_key
        self.assertEqual(blind_index(k, "Bob@Mail.com "), blind_index(k, "bob@mail.com"))
        self.assertNotEqual(blind_index(k, "bob@mail.com"), blind_index(os.urandom(32), "bob@mail.com"))

    def test_transport_roundtrip_and_replay(self):
        env = client_envelope(self.transport, {"descriptor": [0.1] * 128}, nonce="n" * 32)
        self.assertEqual(self.transport.decrypt(env)["descriptor"][0], 0.1)
        with self.assertRaisesRegex(CryptoError, "Replay"):
            self.transport.decrypt(env)

    def test_transport_rejects_stale(self):
        env = client_envelope(self.transport, {"descriptor": []}, ts=int(time.time() * 1000) - 10 * 60_000)
        with self.assertRaisesRegex(CryptoError, "expired"):
            self.transport.decrypt(env)

    def test_transport_rejects_tamper(self):
        env = client_envelope(self.transport, {"descriptor": []})
        ct = bytearray(base64.b64decode(env["ct"]))
        ct[-1] ^= 1
        env["ct"] = base64.b64encode(bytes(ct)).decode()
        with self.assertRaises(CryptoError):
            self.transport.decrypt(env)


class AuditChainTests(unittest.TestCase):
    def test_tamper_detected(self):
        with tempfile.TemporaryDirectory() as d:
            db = Database(Path(d) / "a.db", os.urandom(32))
            for i in range(5):
                db.audit("alice", "verify", "match", target=str(i))
            self.assertTrue(db.verify_audit_chain()["valid"])
            conn = sqlite3.connect(Path(d) / "a.db")
            conn.execute("UPDATE audit_log SET outcome='no_match' WHERE id=3")
            conn.commit()
            conn.close()
            res = db.verify_audit_chain()
            self.assertFalse(res["valid"])
            self.assertEqual(res["broken_at"], 3)


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = create_app(Path(self.tmp.name), "api-test-pass", ADMIN_PW)
        self.client = self.app.test_client()
        self.svc = self.app.extensions["bfe"]

    def tearDown(self):
        self.tmp.cleanup()

    def env(self, payload):
        return client_envelope(self.svc.transport, payload)

    def login(self, user=SUPER, pw=ADMIN_PW):
        r = self.client.post("/api/auth/login", json={"username": user, "password": pw})
        return r

    def auth(self):
        return {"Authorization": "Bearer " + self.login().get_json()["token"]}

    def enroll(self, headers, name, email, vec, seed=0):
        samples = [noisy(vec, seed + i) for i in range(3)]
        return self.client.post("/api/subjects", headers=headers,
                                json={"name": name, "email": email, "envelope": self.env({"descriptors": samples})})

    def test_security_headers(self):
        r = self.client.get("/api/health")
        self.assertIn("default-src 'self'", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")

    def test_auth_required(self):
        self.assertEqual(self.client.get("/api/subjects").status_code, 401)
        self.assertEqual(self.client.get("/api/subjects",
                                         headers={"Authorization": "Bearer junk"}).status_code, 401)

    def test_bad_login_and_lockout(self):
        for _ in range(5):
            self.assertEqual(self.login(pw="wrong").status_code, 401)
        self.assertEqual(self.login().status_code, 423)  # locked even with the right password

    def test_only_super_admin_can_sign_in(self):
        # An extra admin account smuggled into the database still cannot sign in or use the API.
        from werkzeug.security import generate_password_hash
        self.svc.db.create_operator("intruder", generate_password_hash("intruder-pass-1"), "admin")
        self.assertEqual(self.login("intruder", "intruder-pass-1").status_code, 403)
        forged, _ = self.svc.tokens.issue("intruder", "admin")
        h = {"Authorization": f"Bearer {forged}"}
        self.assertEqual(self.client.get("/api/stats", headers=h).status_code, 403)
        self.assertEqual(self.client.post("/api/keys/rotate", headers=h).status_code, 403)

    def test_super_admin_login_is_case_insensitive(self):
        self.assertEqual(self.login("  MukeshRao1704@Gmail.com ").status_code, 200)

    def test_account_creation_disabled(self):
        h = self.auth()
        r = self.client.post("/api/operators", headers=h,
                             json={"username": "op1", "password": "operator-pass-1", "role": "operator"})
        self.assertEqual(r.status_code, 403)
        self.assertEqual([o["username"] for o in self.client.get("/api/operators", headers=h).get_json()], [SUPER])

    def test_verify_is_public_but_enroll_is_not(self):
        r = self.client.post("/api/verify", json={"email": "x@y.io", "envelope": self.env({"descriptor": [0.0] * 128})})
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.get_json()["match"])
        r = self.client.post("/api/subjects", json={"name": "X", "email": "x@y.io",
                                                    "envelope": self.env({"descriptors": [[0.0] * 128]})})
        self.assertEqual(r.status_code, 401)

    def test_logout_revokes_token(self):
        h = self.auth()
        self.client.post("/api/auth/logout", headers=h)
        self.assertEqual(self.client.get("/api/stats", headers=h).status_code, 401)

    def test_full_flow(self):
        h = self.auth()
        alice, bob = rand_vec(10), rand_vec(20)
        r = self.enroll(h, "Alice", "alice@example.com", alice)
        self.assertEqual(r.status_code, 201, r.get_json())
        self.assertEqual(self.enroll(h, "Bob", "bob@example.com", bob, 50).status_code, 201)

        # duplicate e-mail and duplicate face are both rejected
        self.assertEqual(self.enroll(h, "A2", "alice@example.com", rand_vec(30)).status_code, 409)
        self.assertEqual(self.enroll(h, "Evil", "evil@example.com", alice, 90).status_code, 409)

        # database file contains no plaintext
        raw = (Path(self.tmp.name) / "biometric.db").read_bytes()
        self.assertNotIn(b"alice@example.com", raw)
        self.assertNotIn(b"Alice", raw)

        # 1:1 verification
        ok = self.client.post("/api/verify", json={"email": "alice@example.com",
                                                   "envelope": self.env({"descriptor": noisy(alice, 99)})})
        self.assertTrue(ok.get_json()["match"])
        bad = self.client.post("/api/verify", json={"email": "alice@example.com",
                                                    "envelope": self.env({"descriptor": bob})})
        self.assertFalse(bad.get_json()["match"])
        self.assertNotIn("distance", bad.get_json())  # no score leak on failure

        # 1:N identification
        r = self.client.post("/api/identify", headers=h, json={"envelope": self.env({"descriptor": noisy(bob, 5)})})
        self.assertEqual(r.get_json()["name"], "Bob")

        # rotation keeps everything readable
        rot = self.client.post("/api/keys/rotate", headers=h).get_json()
        self.assertEqual(rot["rewrapped"], 2)
        subs = self.client.get("/api/subjects", headers=h).get_json()
        self.assertTrue(all(s["integrity"] == "ok" and s["key_version"] == 2 for s in subs))
        self.assertEqual(self.client.post("/api/keys/1/retire", headers=h).status_code, 200)

        # audit chain is intact
        self.assertTrue(self.client.get("/api/audit/verify", headers=h).get_json()["valid"])

    def test_tampered_row_flagged(self):
        h = self.auth()
        self.enroll(h, "Carol", "carol@example.com", rand_vec(40))
        conn = sqlite3.connect(Path(self.tmp.name) / "biometric.db")
        conn.execute("UPDATE subjects SET pii_ct = zeroblob(length(pii_ct))")
        conn.commit()
        conn.close()
        subs = self.client.get("/api/subjects", headers=h).get_json()
        self.assertEqual(subs[0]["integrity"], "failed")

    def test_invalid_descriptor_rejected(self):
        r = self.client.post("/api/verify", json={"email": "x@y.io",
                                                  "envelope": self.env({"descriptor": [1e9] * 128})})
        self.assertEqual(r.status_code, 400)

    def test_plain_descriptor_without_envelope_rejected(self):
        r = self.client.post("/api/verify", json={"email": "x@y.io", "descriptor": [0.0] * 128})
        self.assertEqual(r.status_code, 400)


if __name__ == "__main__":
    unittest.main()
