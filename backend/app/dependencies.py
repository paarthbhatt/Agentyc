"""Dependency injection for FastAPI."""

from typing import Optional, Annotated
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthCredentials

from app.auth.jwt_handler import verify_token
from app.db.session import get_db
from app.models import User, Organization
from sqlalchemy.orm import Session


security = HTTPBearer()


async def get_current_user(
    credentials: Annotated[HTTPAuthCredentials, Depends(security)],
    db: Annotated[Session, Depends(get_db)],
) -> dict:
    """Get current user from JWT token."""
    token = credentials.credentials

    payload = verify_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(User).filter(User.id == payload.user_id).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    return {
        "user_id": str(payload.user_id),
        "org_id": str(payload.org_id),
        "email": payload.email,
        "role": payload.role,
    }


async def get_current_org(
    current_user: Annotated[dict, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> Organization:
    """Get current organization."""
    org = db.query(Organization).filter(
        Organization.id == current_user["org_id"]
    ).first()

    if not org:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization not found",
        )

    return org


CurrentUser = Annotated[dict, Depends(get_current_user)]
CurrentOrg = Annotated[Organization, Depends(get_current_org)]
