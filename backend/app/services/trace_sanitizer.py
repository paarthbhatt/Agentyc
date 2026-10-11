"""Shared capture-boundary sanitizer for telemetry trace payloads.

Two defensive controls are applied before a trace payload is stored and later
replayed (see reports/replay-robustness-2026-10-11.md, findings R-001 and R-002):

1. Recursive secret redaction. Values under secret-named keys and common
   credential formats embedded in strings are replaced before storage, so they
   never reach SQL, replay responses, streams, or downstream indexing.
2. Recursive size/depth bounds. Depth, node count, per-string length, per-
   container item count, and total serialized bytes are capped. An over-budget
   payload is rejected at validation (HTTP 422) rather than failing later during
   storage or response serialization (HTTP 500).

Both controls run from one place so HTTP capture, SDK capture, and legacy import
share identical limits. Bounds are overridable via environment variables.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Mapping
from typing import Any

REDACTED = "[REDACTED]"

# Case-insensitive substrings that mark a mapping key as holding a secret.
SECRET_KEY_HINTS: tuple[str, ...] = (
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

# Credential formats embedded inside otherwise-free-text string values.
_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]+"),
    re.compile(
        r"(?i)\b(?:api[_-]?key|token|password|passwd|secret|authorization)\s*[=:]\s*[^\s,;&]+"
    ),
    re.compile(r"\bsk-[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])"),
    re.compile(r"\bgh[opsur]_[A-Za-z0-9]{20,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
)


def _env_int(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


MAX_DEPTH = _env_int("TELEMETRY_PAYLOAD_MAX_DEPTH", 32)
MAX_NODES = _env_int("TELEMETRY_PAYLOAD_MAX_NODES", 2000)
MAX_STRING_LEN = _env_int("TELEMETRY_PAYLOAD_MAX_STRING", 16384)
MAX_ITEMS = _env_int("TELEMETRY_PAYLOAD_MAX_ITEMS", 1000)
MAX_BYTES = _env_int("TELEMETRY_PAYLOAD_MAX_BYTES", 262144)


class PayloadBoundsError(ValueError):
    """Raised when a payload exceeds a configured size or depth bound."""


def _is_secret_key(key: str) -> bool:
    low = key.lower()
    return any(hint in low for hint in SECRET_KEY_HINTS)


def scrub_surrogates(value: str) -> str:
    # Unpaired UTF-16 surrogate code points (e.g. "\ud800") cannot be UTF-8
    # encoded and raise UnicodeEncodeError when a capture or replay response is
    # serialized to JSON (an HTTP-500 candidate). Replace them with the Unicode
    # replacement character so storage and replay stay encodable and
    # deterministic. The common case (no surrogate) returns the input untouched.
    try:
        value.encode("utf-8")
        return value
    except UnicodeEncodeError:
        return value.encode("utf-8", "replace").decode("utf-8")


def redact_text(value: str) -> str:
    for pattern in _VALUE_PATTERNS:
        value = pattern.sub(REDACTED, value)
    return scrub_surrogates(value)


def safe_validation_errors(errors: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    # Pydantic's error list echoes the offending `input` (and a `ctx` that may
    # hold the raw exception). For a telemetry product that input can be a
    # secret or a hostile deeply-nested payload, so keep only type/loc/msg
    # (R-001). Dropping `input` also avoids recursing a 1000-deep payload during
    # response serialization (RecursionError). Single source of truth shared by
    # the HTTP exception handler and the robustness harness.
    return [
        {"type": err.get("type"), "loc": err.get("loc"), "msg": err.get("msg")}
        for err in errors
    ]


class _Budget:
    __slots__ = ("nodes", "size")

    def __init__(self) -> None:
        self.nodes = 0
        self.size = 0

    def charge(self, amount: int) -> None:
        self.size += amount
        if self.size > MAX_BYTES:
            raise PayloadBoundsError(f"payload exceeds {MAX_BYTES} serialized bytes")

    def node(self) -> None:
        self.nodes += 1
        if self.nodes > MAX_NODES:
            raise PayloadBoundsError(f"payload exceeds {MAX_NODES} total values")


def _walk(value: Any, depth: int, budget: _Budget) -> Any:
    if depth > MAX_DEPTH:
        raise PayloadBoundsError(f"payload nesting exceeds {MAX_DEPTH} levels")
    budget.node()
    if isinstance(value, dict):
        if len(value) > MAX_ITEMS:
            raise PayloadBoundsError(f"object exceeds {MAX_ITEMS} keys")
        budget.charge(2)
        out: dict[str, Any] = {}
        for raw_key, item in value.items():
            key = str(raw_key)
            budget.charge(len(key) + 4)
            if _is_secret_key(key):
                budget.node()
                out[key] = REDACTED
            else:
                out[key] = _walk(item, depth + 1, budget)
        return out
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_ITEMS:
            raise PayloadBoundsError(f"array exceeds {MAX_ITEMS} items")
        budget.charge(2)
        return [_walk(item, depth + 1, budget) for item in value]
    if isinstance(value, str):
        if len(value) > MAX_STRING_LEN:
            raise PayloadBoundsError(f"string value exceeds {MAX_STRING_LEN} characters")
        budget.charge(len(value) + 2)
        return redact_text(value)
    budget.charge(8)
    return value


def sanitize_payload(payload: Any) -> Any:
    """Return a redacted, bounds-checked copy of a trace payload.

    Non-mapping payloads are returned unchanged (the envelope schema constrains
    the top-level type separately). Raises ``PayloadBoundsError`` when a bound
    is exceeded; callers at the Pydantic boundary surface this as HTTP 422.
    """
    if not isinstance(payload, dict):
        return payload
    return _walk(payload, 1, _Budget())


def redact_only(value: Any, depth: int = 1) -> Any:
    """Recursively redact secret-shaped values without enforcing bounds.

    Applied on the replay/read path so secrets in already-stored (legacy) rows
    are scrubbed before they reach a replay response, stream, or index, even
    though they were written before capture-time redaction existed (R-001).
    Never raises and tolerates any JSON value or over-deep legacy structure.
    """
    if depth > MAX_DEPTH:
        return REDACTED
    if isinstance(value, dict):
        return {
            str(k): (REDACTED if _is_secret_key(str(k)) else redact_only(v, depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact_only(item, depth + 1) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
