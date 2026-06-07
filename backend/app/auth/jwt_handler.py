"""JWT token generation and validation."""

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from pydantic import BaseModel


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


SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-change-in-production")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))


def create_access_token(
    user_id: str,
    org_id: str,
    email: str,
    role: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create access token."""
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )

    payload = {
        "user_id": user_id,
        "org_id": org_id,
        "email": email,
        "role": role,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }

    encoded_jwt = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return encoded_jwt


def create_refresh_token(
    user_id: str,
    org_id: str,
    email: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create refresh token."""
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    payload = {
        "user_id": user_id,
        "org_id": org_id,
        "email": email,
        "type": "refresh",
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }

    encoded_jwt = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return encoded_jwt


def verify_token(token: str) -> Optional[TokenPayload]:
    """Verify and decode token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return TokenPayload(**payload)
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def decode_refresh_token(token: str) -> Optional[dict]:
    """Decode refresh token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        if payload.get("type") != "refresh":
            return None
        return payload
    except jwt.InvalidTokenError:
        return None
