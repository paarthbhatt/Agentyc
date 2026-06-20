"""JWT token generation and validation."""

from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from pydantic import BaseModel

from app.core.config import get_settings


class TokenPayload(BaseModel):
    """JWT token payload."""
    user_id: str
    org_id: str
    email: str
    role: str
    exp: int
    iat: int


class TokenResponse(BaseModel):
    """Token response."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


def _settings():
    """Return the cached application settings (single source of truth for the JWT secret)."""
    return get_settings()


def create_access_token(
    user_id: str,
    org_id: str,
    email: str,
    role: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create access token."""
    settings = _settings()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.access_token_expire_minutes
        )

    payload = {
        "user_id": user_id,
        "org_id": org_id,
        "email": email,
        "role": role,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }

    encoded_jwt = jwt.encode(payload, settings.jwt_secret_key, algorithm="HS256")
    return encoded_jwt


def create_refresh_token(
    user_id: str,
    org_id: str,
    email: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create refresh token."""
    settings = _settings()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)

    payload = {
        "user_id": user_id,
        "org_id": org_id,
        "email": email,
        "type": "refresh",
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }

    encoded_jwt = jwt.encode(payload, settings.jwt_secret_key, algorithm="HS256")
    return encoded_jwt


def verify_token(token: str) -> Optional[TokenPayload]:
    """Verify and decode token."""
    settings = _settings()
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=["HS256"])
        return TokenPayload(**payload)
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def decode_refresh_token(token: str) -> Optional[dict]:
    """Decode refresh token."""
    settings = _settings()
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=["HS256"])
        if payload.get("type") != "refresh":
            return None
        return payload
    except jwt.InvalidTokenError:
        return None
