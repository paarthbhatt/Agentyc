"""API key management service."""

import hashlib
import secrets
import string
from typing import Optional

from app.auth.password import hash_password


def generate_api_key() -> str:
    """Generate a random API key."""
    chars = string.ascii_letters + string.digits + "-_"
    return "".join(secrets.choice(chars) for _ in range(32))


def hash_api_key(key: str) -> str:
    """Hash an API key for storage."""
    return hashlib.sha256(key.encode()).hexdigest()


def verify_api_key(key: str, key_hash: str) -> bool:
    """Verify an API key against its hash."""
    return hash_api_key(key) == key_hash
