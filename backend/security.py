"""Authentication (JWT), authorisation (roles), rate limiting and HTTP security headers."""
from __future__ import annotations

import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import current_app, g, jsonify, request


# --------------------------------------------------------------------------- #
#  JWT session tokens (HS256, short-lived, revocable)
# --------------------------------------------------------------------------- #
class TokenService:
    ALG = "HS256"

    def __init__(self, secret: bytes, ttl_minutes: int):
        self.secret = secret
        self.ttl = timedelta(minutes=ttl_minutes)
        self._revoked: dict[str, float] = {}
        self._lock = threading.Lock()

    def issue(self, username: str, role: str) -> tuple[str, int]:
        now = datetime.now(timezone.utc)
        exp = now + self.ttl
        claims = {"sub": username, "role": role, "iat": now, "nbf": now, "exp": exp,
                  "jti": secrets.token_hex(16), "iss": "bfe"}
        return jwt.encode(claims, self.secret, algorithm=self.ALG), int(self.ttl.total_seconds())

    def verify(self, token: str) -> dict:
        # algorithms=[...] pins the algorithm and blocks the "alg: none" attack
        claims = jwt.decode(token, self.secret, algorithms=[self.ALG], issuer="bfe",
                            options={"require": ["exp", "iat", "jti", "sub"]})
        with self._lock:
            if claims["jti"] in self._revoked:
                raise jwt.InvalidTokenError("Token revoked")
        return claims

    def revoke(self, claims: dict) -> None:
        with self._lock:
            now = time.time()
            for k in [k for k, exp in self._revoked.items() if exp < now]:
                del self._revoked[k]
            self._revoked[claims["jti"]] = float(claims["exp"])


def require_auth(*roles: str):
    """Decorator: valid Bearer token required; optionally restrict to roles."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            header = request.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                return jsonify(error="Authentication required"), 401
            try:
                claims = current_app.extensions["bfe"].tokens.verify(header[7:])
            except jwt.PyJWTError:
                return jsonify(error="Invalid or expired session"), 401
            if claims["sub"] != current_app.config["SUPER_ADMIN"]:
                return jsonify(error="Restricted to the super administrator"), 403
            if roles and claims["role"] not in roles:
                return jsonify(error="Insufficient privileges"), 403
            g.user = claims
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# --------------------------------------------------------------------------- #
#  Sliding-window rate limiter (in-memory, per client IP + bucket)
# --------------------------------------------------------------------------- #
class RateLimiter:
    def __init__(self):
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window: int) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and q[0] <= now - window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True


def rate_limit(bucket: str, limit: int, window: int):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            limiter = current_app.extensions["bfe"].limiter
            if not limiter.allow(f"{bucket}:{client_ip()}", limit, window):
                return jsonify(error="Too many requests, slow down"), 429
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def client_ip() -> str:
    return request.remote_addr or "unknown"


# --------------------------------------------------------------------------- #
#  HTTP security headers
# --------------------------------------------------------------------------- #
CSP = "; ".join([
    "default-src 'self'",
    "script-src 'self' 'wasm-unsafe-eval'",   # everything is bundled locally, no CDN
    "connect-src 'self'",
    "img-src 'self' data: blob:",
    "media-src 'self' blob:",
    "style-src 'self'",
    "font-src 'self'",
    "worker-src 'self' blob:",
    "object-src 'none'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
])


def apply_security_headers(response):
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(self), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response
