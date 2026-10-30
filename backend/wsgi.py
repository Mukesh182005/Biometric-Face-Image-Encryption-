"""Production entry point:  gunicorn -w 1 --threads 8 -b 0.0.0.0:$PORT wsgi:app

Run exactly ONE worker process. The RSA transport key, the replay-nonce cache, the rate limiter and the
token denylist live in memory, and each process would hold its own copy of the keyring keys.
Use threads (not workers) for concurrency.
"""
from app import create_app

app = create_app()
