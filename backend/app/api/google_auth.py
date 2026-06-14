"""Google OAuth2 authentication routes."""

import uuid
import urllib.parse

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.auth import create_access_token, create_refresh_token, hash_password
from app.core.config import get_settings
from app.db.session import get_db
from app.models import User, Organization, OrganizationMember
from app.schemas import AuthTokenResponse, UserRead, OrganizationRead

router = APIRouter(prefix="/api/v1/auth/google", tags=["auth"])

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"


@router.get("/login")
async def google_login():
    """Redirect the browser to Google's OAuth consent screen."""
    settings = get_settings()
    if not settings.google_client_id:
        raise HTTPException(status_code=501, detail="Google OAuth not configured")

    params = {
        "client_id": settings.google_client_id,
        "redirect_uri": settings.oauth_redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "select_account",
    }
    url = GOOGLE_AUTH_URL + "?" + urllib.parse.urlencode(params)
    return RedirectResponse(url)


@router.get("/callback")
async def google_callback(code: str, db: Session = Depends(get_db)):
    """Exchange the Google code for tokens, upsert user, return JWT."""
    settings = get_settings()
    if not settings.google_client_id:
        raise HTTPException(status_code=501, detail="Google OAuth not configured")

    # Exchange code for tokens
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            GOOGLE_TOKEN_URL,
            data={
                "code": code,
                "client_id": settings.google_client_id,
                "client_secret": settings.google_client_secret,
                "redirect_uri": settings.oauth_redirect_uri,
                "grant_type": "authorization_code",
            },
        )
    if token_resp.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to exchange Google code")

    token_data = token_resp.json()
    google_access_token = token_data.get("access_token")

    # Get user info
    async with httpx.AsyncClient() as client:
        user_resp = await client.get(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {google_access_token}"},
        )
    if user_resp.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to get Google user info")

    google_info = user_resp.json()
    email: str = google_info.get("email", "")
    if not email:
        raise HTTPException(status_code=400, detail="Google account has no email")

    # Upsert user
    user = db.query(User).filter(User.email == email).first()
    if not user:
        user = User(
            email=email,
            password_hash=hash_password(str(uuid.uuid4())),  # random unusable password
            is_active=True,
        )
        db.add(user)
        db.flush()

        # Create org for new Google user
        slug = email.split("@")[0].lower().replace(".", "-") + "-" + str(uuid.uuid4())[:8]
        org = Organization(name=google_info.get("name", email), slug=slug, owner_id=user.id)
        db.add(org)
        db.flush()

        member = OrganizationMember(org_id=org.id, user_id=user.id, role="owner")
        db.add(member)
        db.commit()
    else:
        member = db.query(OrganizationMember).filter(OrganizationMember.user_id == user.id).first()
        if not member:
            raise HTTPException(status_code=403, detail="User not part of any organization")
        org = db.query(Organization).filter(Organization.id == member.org_id).first()

    # Issue JWT tokens
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

    # Redirect to frontend with tokens in query params
    frontend_url = settings.oauth_redirect_uri.replace("/auth/callback", "")
    redirect = (
        f"{frontend_url}/auth/callback"
        f"?access_token={access_token}"
        f"&refresh_token={refresh_token}"
    )
    return RedirectResponse(redirect)
