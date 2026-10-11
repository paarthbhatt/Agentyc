from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"

_SECRET_KEY_HINTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "api-key",
    "x-api-key",
    "authorization",
    "auth_token",
    "access_key",
    "accesskey",
    "credential",
    "private_key",
    "privatekey",
    "client_secret",
    "session_key",
    "cookie",
    "bearer",
)

_VALUE_PATTERNS = (
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]+"),
    re.compile(r"(?i)\b(?:api[_-]?key|token|password|passwd|secret|authorization)\s*[=:]\s*[^\s,;&]+"),
    re.compile(r"\bsk-[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])"),
    re.compile(r"\bgh[opsur]_[A-Za-z0-9]{20,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
)

_MAX_DEPTH = 32


def _is_secret_key(key: str) -> bool:
    low = key.lower()
    return any(hint in low for hint in _SECRET_KEY_HINTS)


def redact(value: Any, depth: int = 1) -> Any:
    """Recursively redact secret-shaped values before they leave the client.

    Mirrors the server capture-boundary policy so credentials are never put on
    the wire, even though the server also redacts on receipt (defense in depth).
    """
    if depth > _MAX_DEPTH:
        return REDACTED
    if isinstance(value, dict):
        return {
            str(k): (REDACTED if _is_secret_key(str(k)) else redact(v, depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item, depth + 1) for item in value]
    if isinstance(value, str):
        for pattern in _VALUE_PATTERNS:
            value = pattern.sub(REDACTED, value)
        return value
    return value
