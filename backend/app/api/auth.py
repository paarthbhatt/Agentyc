"""Authentication routes."""

from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.auth import (
    create_access_token,
    create_refresh_token,
    hash_password,
    verify_password,
    decode_refresh_token,
)
from app.db.session import get_db
from app.dependencies import CurrentUser, CurrentOrg
from app.models import User, Organization, OrganizationMember
from app.schemas import (
    UserRegister,
    UserLogin,
    TokenRefresh,
    AuthTokenResponse,
    UserRead,
    OrganizationRead,
)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/register", response_model=AuthTokenResponse)
async def register(
    payload: UserRegister,
    db: Annotated[Session, Depends(get_db)],
):
    """Register new user and create organization."""
    # Check if user exists
    existing_user = db.query(User).filter(User.email == payload.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists",
        )

    # Create user
    user = User(
        email=payload.email,
        password_hash=hash_password(payload.password),
        is_active=True,
    )
    db.add(user)
    db.flush()

    # Create organization
    slug = payload.org_name.lower().replace(" ", "-")
    org = Organization(
        name=payload.org_name,
        slug=slug,
        owner_id=user.id,
    )
    db.add(org)
    db.flush()

    # Create member (owner)
    member = OrganizationMember(
        org_id=org.id,
        user_id=user.id,
        role="owner",
    )
    db.add(member)
    db.commit()

    # Create tokens
    access_token = create_access_token(
        user_id=str(user.id),
        org_id=str(org.id),
        email=user.email,
        role="owner",
    )
    refresh_token = create_refresh_token(
        user_id=str(user.id),
        org_id=str(org.id),
        email=user.email,
    )

    return AuthTokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user=UserRead.model_validate(user),
        organization=OrganizationRead.model_validate(org),
    )


@router.post("/login", response_model=AuthTokenResponse)
async def login(
    payload: UserLogin,
    db: Annotated[Session, Depends(get_db)],
):
    """Login user."""
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )

    # Get user's organization (primary member role)
    member = db.query(OrganizationMember).filter(
        OrganizationMember.user_id == user.id
    ).first()
    if not member:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User not part of any organization",
        )

    org = db.query(Organization).filter(
        Organization.id == member.org_id
    ).first()

    # Create tokens
    access_token = create_access_token(
        user_id=str(user.id),
        org_id=str(org.id),
        email=user.email,
        role=member.role,
    )
    refresh_token = create_refresh_token(
        user_id=str(user.id),
        org_id=str(org.id),
        email=user.email,
    )

    return AuthTokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user=UserRead.model_validate(user),
        organization=OrganizationRead.model_validate(org),
    )


@router.post("/refresh", response_model=AuthTokenResponse)
async def refresh_token(
    payload: TokenRefresh,
    db: Annotated[Session, Depends(get_db)],
):
    """Refresh access token."""
    token_data = decode_refresh_token(payload.refresh_token)
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    user = db.query(User).filter(User.id == token_data["user_id"]).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    org = db.query(Organization).filter(
        Organization.id == token_data["org_id"]
    ).first()
    if not org:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization not found",
        )

    member = db.query(OrganizationMember).filter(
        OrganizationMember.org_id == org.id,
        OrganizationMember.user_id == user.id,
    ).first()

    # Create new tokens
    access_token = create_access_token(
        user_id=str(user.id),
        org_id=str(org.id),
        email=user.email,
        role=member.role if member else "analyst",
    )
    new_refresh_token = create_refresh_token(
        user_id=str(user.id),
        org_id=str(org.id),
        email=user.email,
    )

    return AuthTokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
        user=UserRead.model_validate(user),
        organization=OrganizationRead.model_validate(org),
    )


@router.post("/logout")
async def logout(current_user: CurrentUser):
    """Logout user (client should discard token)."""
    return {"message": "Logged out successfully"}


@router.get("/me", response_model=UserRead)
async def get_current_user_info(current_user: CurrentUser):
    """Get current user info."""
    return {
        "id": current_user["user_id"],
        "email": current_user["email"],
        "is_active": True,
    }


# API Key Management Endpoints

from app.models import APIKey
from app.schemas import APIKeyCreate, APIKeyRead
from app.services.api_key_service import generate_api_key, hash_api_key
from datetime import datetime, timezone


@router.post("/api-keys", response_model=dict)
async def create_api_key(
    payload: APIKeyCreate,
    current_user: CurrentUser,
    org: CurrentOrg,
    db: Annotated[Session, Depends(get_db)],
):
    """Create a new API key."""
    key = generate_api_key()
    key_hash = hash_api_key(key)

    api_key = APIKey(
        org_id=org.id,
        user_id=current_user["user_id"],
        key_hash=key_hash,
        name=payload.name,
        expires_at=payload.expires_at,
    )
    db.add(api_key)
    db.commit()

    return {
        "id": str(api_key.id),
        "key": key,  # Only return full key once
        "name": api_key.name,
        "created_at": api_key.created_at,
        "expires_at": api_key.expires_at,
    }


@router.get("/api-keys")
async def list_api_keys(
    current_user: CurrentUser,
    org: CurrentOrg,
    db: Annotated[Session, Depends(get_db)],
):
    """List API keys for organization."""
    keys = db.query(APIKey).filter(
        APIKey.org_id == org.id,
        APIKey.user_id == current_user["user_id"],
    ).all()

    return [
        {
            "id": str(k.id),
            "name": k.name,
            "created_at": k.created_at,
            "expires_at": k.expires_at,
        }
        for k in keys
    ]


@router.delete("/api-keys/{key_id}")
async def delete_api_key(
    key_id: str,
    current_user: CurrentUser,
    org: CurrentOrg,
    db: Annotated[Session, Depends(get_db)],
):
    """Delete an API key."""
    key = db.query(APIKey).filter(
        APIKey.id == key_id,
        APIKey.org_id == org.id,
        APIKey.user_id == current_user["user_id"],
    ).first()

    if not key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )

    db.delete(key)
    db.commit()

    return {"message": "API key deleted"}

