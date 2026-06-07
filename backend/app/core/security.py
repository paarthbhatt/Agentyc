from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Final

from app.core.config import get_settings

API_KEY_PREFIX: Final[str] = "ags_"


def generate_api_key() -> str:
    return API_KEY_PREFIX + secrets.token_urlsafe(32)


def hash_api_key(api_key: str) -> str:
    pepper = get_settings().api_key_pepper.encode("utf-8")
    return hmac.new(pepper, api_key.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_api_key(api_key: str, expected_hash: str) -> bool:
    if not api_key or not expected_hash:
        return False
    return hmac.compare_digest(hash_api_key(api_key), expected_hash)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
