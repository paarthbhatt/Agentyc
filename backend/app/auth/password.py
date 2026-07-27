"""Password hashing with bcrypt and SHA-256 length normalization."""

from __future__ import annotations

import base64
import hashlib

import bcrypt

SCHEME_PREFIX = "$sentinel-bcrypt-sha256$"


def _normalized(password: str) -> bytes:
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.b64encode(digest)


def hash_password(password: str) -> str:
    hashed = bcrypt.hashpw(_normalized(password), bcrypt.gensalt()).decode("ascii")
    return SCHEME_PREFIX + hashed


def verify_password(password: str, hashed: str) -> bool:
    try:
        if hashed.startswith(SCHEME_PREFIX):
            stored = hashed.removeprefix(SCHEME_PREFIX).encode("ascii")
            return bcrypt.checkpw(_normalized(password), stored)
        # Compatibility with hashes generated before the normalized scheme.
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("ascii"))
    except (ValueError, UnicodeError):
        return False
