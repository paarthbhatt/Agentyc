"""Compatibility exports for the canonical API authentication dependencies."""

from app.api.auth import (
    Principal,
    get_agent_principal,
    get_current_org,
    get_current_principal,
    get_current_user,
    require_org_admin,
)

__all__ = [
    "Principal",
    "get_agent_principal",
    "get_current_org",
    "get_current_principal",
    "get_current_user",
    "require_org_admin",
]
