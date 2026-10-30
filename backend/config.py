"""Central configuration. Every value can be set in the project's .env file or as an environment variable."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent
ENV_FILE = PROJECT_DIR / ".env"


def load_env_file(path: Path) -> None:
    """Load KEY=VALUE lines from a .env file. Real environment variables always win over the file."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip().removeprefix("export ").strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()  # inline comment on an unquoted value
        if key and value:
            os.environ.setdefault(key, value)


load_env_file(ENV_FILE)
# Production build of the TypeScript + Tailwind frontend (created by `npm run build` in frontend/).
FRONTEND_DIR = PROJECT_DIR / "frontend" / "dist"

DATA_DIR = Path(os.environ.get("BFE_DATA_DIR", BASE_DIR / "instance"))
DB_PATH = DATA_DIR / "biometric.db"
KEYRING_PATH = DATA_DIR / "keyring.enc"
CERT_DIR = DATA_DIR / "tls"

# Passphrase that protects the keyring file at rest (scrypt -> AES-256-GCM).
# In production this comes from a secrets manager / HSM, never from source code.
DEV_PASSPHRASE = "dev-only-change-me-please"
MASTER_PASSPHRASE = os.environ.get("BFE_MASTER_PASSPHRASE", DEV_PASSPHRASE)

# The single super administrator. Only this account can sign in and use the app;
# creating further accounts is disabled.
SUPER_ADMIN = os.environ.get("BFE_SUPER_ADMIN", "mukeshrao1704@gmail.com").strip().lower()

# Super-admin password. When set (e.g. in .env) it is the source of truth: the stored scrypt hash is
# updated on start-up if it differs. When unset, a random one is generated on first run and printed.
ADMIN_PASSWORD = os.environ.get("BFE_ADMIN_PASSWORD")

# Face matching: Euclidean distance between 128-d descriptors.
# face-api.js recommends 0.6; we use a stricter default to lower false accepts.
MATCH_THRESHOLD = float(os.environ.get("BFE_MATCH_THRESHOLD", "0.5"))
DESCRIPTOR_DIM = 128

# Auth
JWT_TTL_MINUTES = int(os.environ.get("BFE_JWT_TTL_MINUTES", "30"))
MAX_FAILED_LOGINS = 5
LOCKOUT_MINUTES = 15
MIN_PASSWORD_LENGTH = 10

# Transport envelope freshness (anti-replay)
TRANSPORT_MAX_SKEW_SECONDS = 120

# Reverse proxies in front of the app (X-Forwarded-For hops to trust). 0 = direct connections (local).
# Vercel -> Render is 2 hops; Render alone is 1.
TRUSTED_PROXIES = int(os.environ.get("BFE_TRUSTED_PROXIES", "0"))

# Request limits
MAX_CONTENT_LENGTH = 64 * 1024
