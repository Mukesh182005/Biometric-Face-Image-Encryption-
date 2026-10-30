"""
Biometric Face Image Encryption - REST API server.

Run:  python app.py            (HTTP on http://localhost:5000)
      python app.py --https    (self-signed TLS on https://localhost:5443)
"""
from __future__ import annotations

import argparse
import itertools
import re
import secrets
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from flask import Flask, g, jsonify, request, send_from_directory
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

import config
from crypto_engine import (CryptoError, KeyManager, TemplateCipher, TransportCipher,
                           blind_index, euclidean_distance, validate_descriptor)
from database import Database
from security import (RateLimiter, TokenService, apply_security_headers, client_ip, rate_limit,
                      require_auth)

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[A-Za-z]{2,}$")
# Used to keep login timing identical for unknown usernames (prevents user enumeration).
DUMMY_HASH = generate_password_hash(secrets.token_hex(16), method="scrypt")


@dataclass
class Services:
    keys: KeyManager
    db: Database
    templates: TemplateCipher
    transport: TransportCipher
    tokens: TokenService
    limiter: RateLimiter
    threshold: float


def hexpreview(data: bytes, n: int = 24) -> str:
    h = data.hex()
    return h if len(h) <= n * 2 else h[: n * 2] + "…"


def mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    return (local[0] + "***" if local else "***") + "@" + domain


def create_app(data_dir: Path | None = None, passphrase: str | None = None,
               admin_password: str | None = None) -> Flask:
    data_dir = Path(data_dir or config.DATA_DIR)
    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = config.MAX_CONTENT_LENGTH
    app.config["SUPER_ADMIN"] = config.SUPER_ADMIN

    keys = KeyManager(data_dir / "keyring.enc", passphrase or config.MASTER_PASSPHRASE)
    db = Database(data_dir / "biometric.db", keys.audit_key)
    svc = Services(keys=keys, db=db, templates=TemplateCipher(keys),
                   transport=TransportCipher(config.TRANSPORT_MAX_SKEW_SECONDS),
                   tokens=TokenService(keys.jwt_secret, config.JWT_TTL_MINUTES),
                   limiter=RateLimiter(), threshold=config.MATCH_THRESHOLD)
    app.extensions["bfe"] = svc

    if (passphrase or config.MASTER_PASSPHRASE) == config.DEV_PASSPHRASE:
        app.logger.warning("Using the DEVELOPMENT keyring passphrase. Set BFE_MASTER_PASSPHRASE "
                           "before storing real biometric data.")

    # Bootstrap the single super-administrator account.
    if db.get_operator(config.SUPER_ADMIN) is None:
        pw = admin_password or config.ADMIN_PASSWORD or secrets.token_urlsafe(12)
        db.create_operator(config.SUPER_ADMIN, generate_password_hash(pw, method="scrypt"), "admin")
        db.audit("system", "bootstrap_admin", "ok", target=config.SUPER_ADMIN)
        if not (admin_password or config.ADMIN_PASSWORD):
            cred_file = data_dir / "ADMIN_PASSWORD.txt"
            cred_file.write_text(f"username: {config.SUPER_ADMIN}\npassword: {pw}\n"
                                 "Delete this file after you have signed in and noted the password.\n")
            print("\n" + "=" * 64 + f"\n  Super-admin account created\n  username: {config.SUPER_ADMIN}\n"
                  f"  password: {pw}\n  (also saved to {cred_file})\n" + "=" * 64 + "\n", flush=True)

    app.after_request(apply_security_headers)

    # ------------------------------------------------------------------ #
    #  helpers
    # ------------------------------------------------------------------ #
    def actor() -> str:
        return g.user["sub"] if getattr(g, "user", None) else "anonymous"

    def body() -> dict:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            raise CryptoError("Request body must be a JSON object")
        return data

    def open_envelope(data: dict) -> dict:
        return svc.transport.decrypt(data.get("envelope"))

    def decrypted_gallery():
        """Yield (row, template) for every subject. Plaintext only lives in memory."""
        for row in db.all_subjects():
            try:
                yield row, svc.templates.open_template(row)
            except CryptoError:
                db.audit("system", "integrity_failure", "error", target=row["id"])

    def best_match(probe: list[float]):
        best = None
        for row, tpl in decrypted_gallery():
            d = euclidean_distance(probe, tpl)
            if best is None or d < best[1]:
                best = (row, d)
        return best

    @app.errorhandler(CryptoError)
    def crypto_error(exc):
        db.audit(actor(), "rejected_request", "error", ip=client_ip(), details=str(exc)[:200])
        return jsonify(error=str(exc)), 400

    @app.errorhandler(HTTPException)
    def http_error(exc):
        return jsonify(error=exc.description), exc.code

    @app.errorhandler(Exception)
    def unhandled(exc):  # never leak stack traces to clients
        app.logger.exception("Unhandled error")
        return jsonify(error="Internal server error"), 500

    # ------------------------------------------------------------------ #
    #  frontend
    # ------------------------------------------------------------------ #
    @app.get("/")
    def index():
        if not (config.FRONTEND_DIR / "index.html").exists():
            return ("<h1>Frontend not built</h1><p>Run <code>npm install</code> and <code>npm run build</code> "
                    "in the <code>frontend</code> folder, or start the project with <code>start.bat</code>.</p>", 503)
        return send_from_directory(config.FRONTEND_DIR, "index.html")

    @app.get("/<path:filename>")
    def static_files(filename):
        # Vite build output: hashed bundles in assets/, face models in models/, favicon.
        # send_from_directory rejects path traversal outside FRONTEND_DIR.
        if filename.startswith("api/"):
            return jsonify(error="Not found"), 404
        response = send_from_directory(config.FRONTEND_DIR, filename)
        if filename.startswith("assets/"):
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        return response

    # ------------------------------------------------------------------ #
    #  public endpoints
    # ------------------------------------------------------------------ #
    @app.get("/api/health")
    def health():
        return jsonify(status="ok", tls=request.is_secure)

    @app.get("/api/crypto/public-key")
    def public_key():
        return jsonify(alg="RSA-OAEP-256+A256GCM", key_size=3072, spki=svc.transport.public_spki_b64,
                       fingerprint=svc.transport.fingerprint)

    @app.post("/api/auth/login")
    @rate_limit("login", limit=10, window=60)
    def login():
        data = body()
        username = str(data.get("username", "")).strip().lower()
        password = str(data.get("password", ""))
        op = db.get_operator(username)
        now = time.time()
        if op and op["locked_until"] and op["locked_until"] > now:
            db.audit(username, "login", "locked", ip=client_ip())
            return jsonify(error="Account temporarily locked after repeated failures"), 423
        valid = check_password_hash(op["password_hash"] if op else DUMMY_HASH, password)
        if not op or not valid:
            if op:
                db.record_login_failure(username, config.MAX_FAILED_LOGINS,
                                        config.LOCKOUT_MINUTES * 60, now)
            db.audit(username or "?", "login", "denied", ip=client_ip())
            return jsonify(error="Invalid username or password"), 401
        if username != config.SUPER_ADMIN:
            # Only the super administrator may use FaceVault.
            db.audit(username, "login", "not_super_admin", ip=client_ip())
            return jsonify(error="Only the super administrator can sign in"), 403
        db.record_login_success(username)
        token, ttl = svc.tokens.issue(username, op["role"])
        db.audit(username, "login", "ok", ip=client_ip())
        return jsonify(token=token, expires_in=ttl, username=username, role=op["role"])

    @app.post("/api/verify")
    @rate_limit("verify", limit=20, window=60)
    def verify():
        """Public 1:1 verification: 'Is this face the person who owns this e-mail?' No sign-in needed."""
        data = body()
        email = str(data.get("email", ""))
        payload = open_envelope(data)
        probe = validate_descriptor(payload.get("descriptor"))
        row = db.get_subject_by_index(blind_index(svc.keys.index_key, email))
        if row is None:
            db.audit(actor(), "verify", "unknown_identity", ip=client_ip())
            return jsonify(match=False, message="No match")  # same answer as a wrong face
        distance = euclidean_distance(probe, svc.templates.open_template(row))
        matched = distance <= svc.threshold
        db.audit(actor(), "verify", "match" if matched else "no_match", target=row["id"],
                 ip=client_ip(), details=f"distance={distance:.4f}")
        if not matched:
            # Never return scores for failed attempts (prevents hill-climbing attacks).
            return jsonify(match=False, message="No match")
        name = svc.templates.open_pii(row)["name"]
        return jsonify(match=True, message=f"Identity verified: {name}",
                       distance=round(distance, 4), threshold=svc.threshold)

    # ------------------------------------------------------------------ #
    #  authenticated endpoints
    # ------------------------------------------------------------------ #
    # ------------------------------------------------------------------ #
    #  super-admin endpoints: every route below requires the super admin
    # ------------------------------------------------------------------ #
    @app.get("/api/auth/me")
    @require_auth()
    def me():
        return jsonify(username=g.user["sub"], role=g.user["role"], exp=g.user["exp"])

    @app.post("/api/auth/logout")
    @require_auth()
    def logout():
        svc.tokens.revoke(g.user)
        db.audit(actor(), "logout", "ok", ip=client_ip())
        return jsonify(ok=True)

    @app.get("/api/stats")
    @require_auth()
    def stats():
        s = db.stats()
        s.update(active_key_version=svc.keys.active_version, threshold=svc.threshold,
                 transport_fingerprint=svc.transport.fingerprint, tls=request.is_secure)
        return jsonify(s)

    @app.post("/api/subjects")
    @require_auth("admin", "operator")
    @rate_limit("enroll", limit=30, window=60)
    def enroll():
        data = body()
        name = str(data.get("name", "")).strip()
        email = str(data.get("email", "")).strip().lower()
        if not (1 <= len(name) <= 100):
            return jsonify(error="Name must be 1-100 characters"), 400
        if not EMAIL_RE.match(email):
            return jsonify(error="Invalid e-mail address"), 400
        payload = open_envelope(data)
        samples = payload.get("descriptors")
        if not isinstance(samples, list) or not 1 <= len(samples) <= 5:
            return jsonify(error="Provide between 1 and 5 face samples"), 400
        samples = [validate_descriptor(s) for s in samples]

        # Quality gate: all captures must look like the same face.
        spread = max((euclidean_distance(a, b) for a, b in itertools.combinations(samples, 2)),
                     default=0.0)
        if spread > 0.45:
            return jsonify(error=f"Samples are inconsistent (max spread {spread:.2f}). "
                                 "Keep one face centred and well lit, then retry."), 400
        template = [sum(col) / len(samples) for col in zip(*samples)]

        index = blind_index(svc.keys.index_key, email)
        if db.get_subject_by_index(index):
            return jsonify(error="This e-mail is already enrolled"), 409
        dup = best_match(template)
        if dup and dup[1] <= svc.threshold:
            db.audit(actor(), "enroll", "duplicate_face", target=dup[0]["id"], ip=client_ip())
            return jsonify(error="This face is already enrolled under another identity"), 409

        record_id = str(uuid.uuid4())
        sealed = svc.templates.seal(record_id, template, {"name": name, "email": email})
        db.insert_subject(record_id, index, sealed, len(samples), actor())
        db.audit(actor(), "enroll", "ok", target=record_id, ip=client_ip(),
                 details=f"samples={len(samples)} key_v={sealed['key_version']}")
        return jsonify(id=record_id, key_version=sealed["key_version"], samples=len(samples),
                       spread=round(spread, 4),
                       stored={"template_ciphertext_bytes": len(sealed["template_ct"]),
                               "template_ciphertext_preview": hexpreview(sealed["template_ct"]),
                               "wrapped_dek_preview": hexpreview(sealed["wrapped_dek"]),
                               "email_blind_index": index}), 201

    @app.get("/api/subjects")
    @require_auth("admin", "operator")
    def list_subjects():
        out = []
        for row in db.all_subjects():
            try:
                pii = svc.templates.open_pii(row)
                out.append({"id": row["id"], "name": pii["name"], "email": mask_email(pii["email"]),
                            "key_version": row["key_version"], "samples": row["samples"],
                            "created_at": row["created_at"], "created_by": row["created_by"],
                            "integrity": "ok"})
            except CryptoError:
                out.append({"id": row["id"], "name": "⚠ TAMPERED", "email": "-",
                            "key_version": row["key_version"], "samples": row["samples"],
                            "created_at": row["created_at"], "created_by": row["created_by"],
                            "integrity": "failed"})
        db.audit(actor(), "list_subjects", "ok", ip=client_ip())
        return jsonify(out)

    @app.delete("/api/subjects/<record_id>")
    @require_auth("admin")
    def delete_subject(record_id):
        if not db.delete_subject(record_id):
            return jsonify(error="Not found"), 404
        db.audit(actor(), "delete_subject", "ok", target=record_id, ip=client_ip())
        return jsonify(ok=True)

    @app.post("/api/identify")
    @require_auth("admin", "operator")
    @rate_limit("identify", limit=30, window=60)
    def identify():
        """1:N identification: 'Who is this face?'"""
        probe = validate_descriptor(open_envelope(body()).get("descriptor"))
        best = best_match(probe)
        if not best or best[1] > svc.threshold:
            db.audit(actor(), "identify", "no_match", ip=client_ip())
            return jsonify(match=False, gallery_size=len(db.all_subjects()))
        row, distance = best
        pii = svc.templates.open_pii(row)
        db.audit(actor(), "identify", "match", target=row["id"], ip=client_ip(),
                 details=f"distance={distance:.4f}")
        return jsonify(match=True, id=row["id"], name=pii["name"], email=mask_email(pii["email"]),
                       distance=round(distance, 4), threshold=svc.threshold)

    @app.get("/api/inspector")
    @require_auth("admin", "operator")
    def inspector():
        """Shows exactly what an attacker who steals the database file would see."""
        rows = [{
            "id": r["id"],
            "email_index": r["email_index"],
            "template_ct": hexpreview(r["template_ct"], 40),
            "template_ct_len": len(r["template_ct"]),
            "template_nonce": r["template_nonce"].hex(),
            "pii_ct": hexpreview(r["pii_ct"], 24),
            "wrapped_dek": hexpreview(r["wrapped_dek"], 24),
            "key_version": r["key_version"],
        } for r in db.all_subjects()]
        db.audit(actor(), "inspect_db", "ok", ip=client_ip())
        return jsonify(rows)

    @app.post("/api/crypto/demo")
    @require_auth("admin", "operator")
    def crypto_demo():
        """Walk through every cryptographic step for one captured face (nothing is stored)."""
        payload = open_envelope(body())
        vec = validate_descriptor(payload.get("descriptor"))
        rid = f"demo-{uuid.uuid4()}"
        sealed = svc.templates.seal(rid, vec, {"name": "demo", "email": "demo@example.com"})
        row = dict(id=rid, **sealed)
        roundtrip = svc.templates.open_template(row)
        max_err = max(abs(a - b) for a, b in zip(vec, roundtrip))

        tampered = dict(row)
        ct = bytearray(sealed["template_ct"])
        ct[0] ^= 0x01
        tampered["template_ct"] = bytes(ct)
        try:
            svc.templates.open_template(tampered)
            tamper_result = "NOT detected (unexpected!)"
        except CryptoError as exc:
            tamper_result = f"Detected - {exc}"

        swapped = dict(row, id=f"demo-{uuid.uuid4()}")
        try:
            svc.templates.open_template(swapped)
            swap_result = "NOT detected (unexpected!)"
        except CryptoError as exc:
            swap_result = f"Detected - {exc}"

        return jsonify(steps=[
            {"step": "1. Transport envelope decrypted",
             "detail": "RSA-OAEP-3072/SHA-256 unwrapped the one-time AES-256-GCM key; "
                       "timestamp + nonce passed the replay check."},
            {"step": "2. Feature vector serialised",
             "detail": f"128 x float32 little-endian = 512 bytes. First values: "
                       f"{[round(v, 4) for v in vec[:6]]}"},
            {"step": "3. Fresh 256-bit DEK generated", "detail": "os.urandom via AESGCM.generate_key"},
            {"step": "4. Template encrypted (AES-256-GCM)",
             "detail": f"nonce={sealed['template_nonce'].hex()} ciphertext+tag="
                       f"{len(sealed['template_ct'])} bytes: {hexpreview(sealed['template_ct'], 32)}"},
            {"step": "5. DEK wrapped with KEK v%d" % sealed["key_version"],
             "detail": f"HKDF-SHA256 derived KEK; wrapped DEK = {hexpreview(sealed['wrapped_dek'], 30)}"},
            {"step": "6. Decrypt round-trip", "detail": f"max abs error = {max_err:.2e} (float32 precision)"},
            {"step": "7. Tamper test (1 bit flipped)", "detail": tamper_result},
            {"step": "8. Row-swap test (ciphertext moved to another id)", "detail": swap_result},
        ])

    # ------------------------------------------------------------------ #
    #  admin endpoints
    # ------------------------------------------------------------------ #
    @app.get("/api/audit")
    @require_auth("admin")
    def audit_log():
        return jsonify([dict(r) for r in db.audit_entries()])

    @app.get("/api/audit/verify")
    @require_auth("admin")
    def audit_verify():
        result = db.verify_audit_chain()
        db.audit(actor(), "verify_audit_chain", "ok" if result["valid"] else "broken", ip=client_ip())
        return jsonify(result)

    @app.get("/api/keys")
    @require_auth("admin")
    def key_status():
        usage = db.key_version_usage()
        return jsonify(active=svc.keys.active_version,
                       versions=[dict(v, records=usage.get(v["version"], 0)) for v in svc.keys.versions()])

    @app.post("/api/keys/rotate")
    @require_auth("admin")
    def rotate_keys():
        new_v = svc.keys.rotate()
        rewrapped = failed = 0
        for row in db.all_subjects():
            try:
                wrapped, v = svc.templates.rewrap(row)
                db.update_wrapped_dek(row["id"], wrapped, v)
                rewrapped += 1
            except CryptoError:
                failed += 1
        db.audit(actor(), "rotate_kek", "ok", ip=client_ip(),
                 details=f"new_v={new_v} rewrapped={rewrapped} failed={failed}")
        return jsonify(active=new_v, rewrapped=rewrapped, failed=failed)

    @app.post("/api/keys/<int:version>/retire")
    @require_auth("admin")
    def retire_key(version):
        if db.key_version_usage().get(version):
            return jsonify(error="Key version still in use"), 409
        svc.keys.retire(version)
        db.audit(actor(), "retire_kek", "ok", target=str(version), ip=client_ip())
        return jsonify(ok=True)

    @app.get("/api/operators")
    @require_auth("admin")
    def list_ops():
        return jsonify([dict(r) for r in db.list_operators()])

    @app.post("/api/operators")
    @require_auth("admin")
    def create_op():
        """Account creation is disabled: FaceVault has exactly one super administrator."""
        db.audit(actor(), "create_operator", "denied", ip=client_ip(), details="account creation disabled")
        return jsonify(error="Creating accounts is disabled. Only the super administrator can use FaceVault."), 403

    return app


def ensure_self_signed_cert(cert_dir: Path) -> tuple[str, str]:
    """Generate a self-signed TLS certificate for localhost (development only)."""
    import datetime as dt
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_path, key_path = cert_dir / "cert.pem", cert_dir / "key.pem"
    if cert_path.exists() and key_path.exists():
        return str(cert_path), str(key_path)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                critical=False)
            .sign(key, hashes.SHA256()))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(cert_path), str(key_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Biometric Face Encryption server")
    parser.add_argument("--https", action="store_true", help="serve over TLS with a self-signed cert")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int)
    parser.add_argument("--no-browser", action="store_true", help="do not open a browser tab")
    args = parser.parse_args()
    application = create_app()
    ssl_ctx = ensure_self_signed_cert(config.CERT_DIR) if args.https else None
    port = args.port or (5443 if args.https else 5000)
    url = f"{'https' if args.https else 'http'}://localhost:{port}"
    print(f"\n  FaceVault is running ->  {url}\n  Press CTRL+C to stop.\n", flush=True)
    if not args.no_browser:
        import threading
        import webbrowser
        threading.Timer(1.5, webbrowser.open, args=(url,)).start()
    application.run(host=args.host, port=port, ssl_context=ssl_ctx, debug=False,
                    threaded=True)
