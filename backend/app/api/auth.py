import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from app.auth import (
    create_access_token,
    create_refresh_token,
    hash_password,
    verify_password,
    verify_token,
)
from app.db.session import get_db
from app.models import Organization, OrganizationMember, User
from app.schemas import AuthTokenResponse, UserLogin, UserRegister

router = APIRouter(prefix="/auth", tags=["auth"])


def get_current_user(
    authorization: str = Header(default=""), db: Session = Depends(get_db)
) -> User:
    """
    JWT/OIDC Validator.
    Validates Bearer JWT tokens issued by the login/register endpoints.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401, detail="Missing or invalid Authorization header"
        )

    token_str = authorization.split(" ")[1]
    payload = verify_token(token_str)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user = db.query(User).filter(User.id == uuid.UUID(payload.user_id)).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Inactive user")

    return user


def get_current_org(
    x_org_id: Optional[str] = Header(default=None),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Organization:
    """
    Resolves the tenant context for the request.
    If x_org_id is provided, verifies the user belongs to it.
    Otherwise defaults to the user's first organization.
    """
    if x_org_id:
        try:
            org_id = uuid.UUID(x_org_id)
            membership = (
                db.query(OrganizationMember)
                .filter(
                    OrganizationMember.user_id == user.id,
                    OrganizationMember.org_id == org_id,
                )
                .first()
            )
            if not membership:
                raise HTTPException(
                    status_code=403, detail="Not a member of this organization"
                )
            return membership.organization
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid org_id format")

    # Default to first org
    membership = (
        db.query(OrganizationMember)
        .filter(OrganizationMember.user_id == user.id)
        .first()
    )
    if membership:
        return membership.organization

    # Auto-provision a default org for prototype
    org = db.query(Organization).filter(Organization.slug == "default").first()
    if not org:
        org = Organization(name="Default Org", slug="default", owner_id=user.id)
        db.add(org)
        db.commit()
        db.refresh(org)

    # Add membership
    mem = OrganizationMember(org_id=org.id, user_id=user.id, role="admin")
    db.add(mem)
    db.commit()

    return org


@router.post("/login", response_model=AuthTokenResponse)
def login(request: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid email or password")

    if not verify_password(request.password, user.password_hash):
        raise HTTPException(status_code=400, detail="Invalid email or password")

    org = (
        db.query(OrganizationMember)
        .filter(OrganizationMember.user_id == user.id)
        .first()
    )
    if org:
        org = org.organization
    else:
        # fallback
        org = db.query(Organization).first()

    access_token = create_access_token(
        user_id=str(user.id),
        org_id=str(org.id) if org else "",
        email=user.email,
        role="admin",
    )
    refresh_token = create_refresh_token(
        user_id=str(user.id), org_id=str(org.id) if org else "", email=user.email
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": user,
        "organization": org,
    }


@router.post("/register", response_model=AuthTokenResponse)
def register(request: UserRegister, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()
    if user:
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        email=request.email,
        password_hash=hash_password(request.password),
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    slug = request.org_name.lower().replace(" ", "-") + "-" + str(uuid.uuid4())[:8]
    org = Organization(name=request.org_name, slug=slug, owner_id=user.id)
    db.add(org)
    db.commit()
    db.refresh(org)

    mem = OrganizationMember(org_id=org.id, user_id=user.id, role="owner")
    db.add(mem)
    db.commit()

    access_token = create_access_token(
        user_id=str(user.id), org_id=str(org.id), email=user.email, role="owner"
    )
    refresh_token = create_refresh_token(
        user_id=str(user.id), org_id=str(org.id), email=user.email
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": user,
        "organization": org,
    }
