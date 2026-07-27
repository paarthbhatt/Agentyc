"""JWT token generation and validation."""

import uuid
from datetime import datetime, timedelta, timezone

import jwt
from pydantic import BaseModel

from app.core.config import get_settings


class TokenPayload(BaseModel):
    """JWT token payload."""

    user_id: str
    org_id: str
    email: str
    role: str
    jti: str
    type: str = "access"
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
    expires_delta: timedelta | None = None,
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
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "sub": user_id,
        "user_id": user_id,
        "org_id": org_id,
        "email": email,
        "role": role,
        "jti": str(uuid.uuid4()),
        "type": "access",
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }

    encoded_jwt = jwt.encode(payload, settings.jwt_secret_key, algorithm="HS256")
    return encoded_jwt


def create_refresh_token(
    user_id: str,
    org_id: str,
    email: str,
    jti: str | None = None,
    expires_delta: timedelta | None = None,
) -> str:
    """Create refresh token."""
    settings = _settings()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)

    payload = {
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "sub": user_id,
        "user_id": user_id,
        "org_id": org_id,
        "email": email,
        "type": "refresh",
        "jti": jti or str(uuid.uuid4()),
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }

    encoded_jwt = jwt.encode(payload, settings.jwt_secret_key, algorithm="HS256")
    return encoded_jwt


def verify_token(token: str) -> TokenPayload | None:
    """Verify and decode token."""
    settings = _settings()
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=["HS256"],
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
        )
        if payload.get("type") != "access":
            return None
        return TokenPayload(**payload)
    except jwt.ExpiredSignatureError:
        return None
    except (jwt.InvalidTokenError, ValueError, TypeError):
        return None


def decode_refresh_token(token: str) -> dict | None:
    """Decode refresh token."""
    settings = _settings()
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=["HS256"],
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
        )
        if payload.get("type") != "refresh":
            return None
        return payload
    except (jwt.InvalidTokenError, ValueError, TypeError):
        return None
