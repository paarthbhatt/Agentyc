"""Google OAuth 2.0 authorization-code flow with state and PKCE."""

from __future__ import annotations

import base64
import hashlib
import secrets
import urllib.parse
import uuid

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.api.auth import _issue_tokens, _set_session_cookies
from app.auth import hash_password
from app.core.config import get_settings
from app.db.session import get_db
from app.models import Organization, OrganizationMember, User

router = APIRouter(prefix="/api/v1/auth/google", tags=["auth"])

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
OAUTH_STATE_COOKIE = "sentinel_oauth_state"
OAUTH_VERIFIER_COOKIE = "sentinel_oauth_verifier"


def _oauth_cookie_options() -> dict:
    settings = get_settings()
    return {
        "httponly": True,
        "secure": settings.cookie_secure,
        "samesite": "lax",
        "max_age": 600,
        "path": "/api/v1/auth/google",
        "domain": settings.cookie_domain,
    }


@router.get("/login")
async def google_login():
    settings = get_settings()
    if not settings.google_client_id or not settings.google_client_secret:
        raise HTTPException(status_code=501, detail="Google OAuth not configured")

    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    params = {
        "client_id": settings.google_client_id,
        "redirect_uri": settings.oauth_callback_url,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "select_account",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    response = RedirectResponse(GOOGLE_AUTH_URL + "?" + urllib.parse.urlencode(params))
    response.set_cookie(OAUTH_STATE_COOKIE, state, **_oauth_cookie_options())
    response.set_cookie(OAUTH_VERIFIER_COOKIE, verifier, **_oauth_cookie_options())
    return response


@router.get("/callback")
async def google_callback(
    request: Request,
    code: str,
    state: str,
    db: Session = Depends(get_db),
):
    settings = get_settings()
    expected_state = request.cookies.get(OAUTH_STATE_COOKIE, "")
    verifier = request.cookies.get(OAUTH_VERIFIER_COOKIE, "")
    if not expected_state or not verifier or not secrets.compare_digest(state, expected_state):
        raise HTTPException(status_code=400, detail="Invalid OAuth state")

    async with httpx.AsyncClient(timeout=10.0) as client:
        token_resp = await client.post(
            GOOGLE_TOKEN_URL,
            data={
                "code": code,
                "client_id": settings.google_client_id,
                "client_secret": settings.google_client_secret,
                "redirect_uri": settings.oauth_callback_url,
                "grant_type": "authorization_code",
                "code_verifier": verifier,
            },
        )
        if token_resp.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to exchange Google code")
        google_access_token = token_resp.json().get("access_token")
        if not google_access_token:
            raise HTTPException(status_code=400, detail="Google returned no access token")
        user_resp = await client.get(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {google_access_token}"},
        )
    if user_resp.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to get Google user info")

    google_info = user_resp.json()
    email = str(google_info.get("email", "")).lower().strip()
    if not email or not google_info.get("email_verified", False):
        raise HTTPException(status_code=400, detail="Google account email is not verified")

    user = db.query(User).filter(User.email == email).one_or_none()
    if user is None:
        user = User(email=email, password_hash=hash_password(str(uuid.uuid4())), is_active=True)
        db.add(user)
        db.flush()
        slug = email.split("@", 1)[0].lower().replace(".", "-") + "-" + str(uuid.uuid4())[:8]
        org = Organization(name=google_info.get("name") or email, slug=slug, owner_id=user.id)
        db.add(org)
        db.flush()
        membership = OrganizationMember(org_id=org.id, user_id=user.id, role="owner")
        db.add(membership)
    else:
        membership = (
            db.query(OrganizationMember)
            .filter(OrganizationMember.user_id == user.id)
            .order_by(OrganizationMember.created_at)
            .first()
        )
        if membership is None:
            raise HTTPException(status_code=403, detail="User has no organization membership")
        org = membership.organization

    access_token, refresh_token, _ = _issue_tokens(db, user=user, org=org, role=membership.role)
    db.commit()
    response = RedirectResponse(settings.frontend_url)
    _set_session_cookies(response, access_token, refresh_token)
    response.delete_cookie(
        OAUTH_STATE_COOKIE, path="/api/v1/auth/google", domain=settings.cookie_domain
    )
    response.delete_cookie(
        OAUTH_VERIFIER_COOKIE, path="/api/v1/auth/google", domain=settings.cookie_domain
    )
    return response
