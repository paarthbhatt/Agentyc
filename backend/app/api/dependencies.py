from __future__ import annotations

import secrets

from fastapi import Depends, Header, HTTPException

from app.api.auth import Principal, get_agent_principal
from app.core.config import get_settings
from app.db.session import get_db


def require_api_key(
    principal: Principal = Depends(get_agent_principal),
) -> Principal:
    return principal


def require_admin_key(x_admin_api_key: str | None = Header(default=None)) -> None:
    """Validate the system bootstrap key, never tenant authorization."""
    expected = get_settings().admin_api_key
    if not expected or not x_admin_api_key or not secrets.compare_digest(x_admin_api_key, expected):
        raise HTTPException(status_code=401, detail="Invalid system bootstrap key")


__all__ = ["get_db", "require_api_key", "require_admin_key"]
