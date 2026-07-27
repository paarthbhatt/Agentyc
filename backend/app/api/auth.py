from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.auth import (
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
    hash_password,
    verify_password,
    verify_token,
)
from app.core.config import get_settings
from app.core.security import hash_api_key, sha256_text
from app.db.session import get_db
from app.models import Agent, Organization, OrganizationMember, RefreshSession, User, utcnow
from app.schemas import (
    AuthSessionResponse,
    AuthTokenResponse,
    OrganizationSwitch,
    TokenRefresh,
    UserLogin,
    UserRegister,
)

router = APIRouter(prefix="/auth", tags=["auth"])

ACCESS_COOKIE = "sentinel_access"
REFRESH_COOKIE = "sentinel_refresh"
CSRF_COOKIE = "sentinel_csrf"
ADMIN_ROLES = {"owner", "admin"}


@dataclass(frozen=True)
class Principal:
    actor_type: Literal["user", "agent"]
    org_id: uuid.UUID
    role: str
    user_id: uuid.UUID | None = None
    agent_id: uuid.UUID | None = None
    scopes: tuple[str, ...] = ()


def _unauthorized(detail: str = "Authentication required") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _bearer_token(authorization: str) -> str | None:
    if not authorization:
        return None
    parts = authorization.split(None, 1)
    if not parts or parts[0].lower() != "bearer":
        return None
    if len(parts) != 2 or not parts[1].strip():
        raise _unauthorized("Missing bearer token")
    return parts[1].strip()


def _request_human_token(request: Request, authorization: str) -> tuple[str, bool]:
    bearer_token = _bearer_token(authorization)
    if bearer_token:
        return bearer_token, False
    cookie_token = request.cookies.get(ACCESS_COOKIE, "")
    if cookie_token:
        return cookie_token, True
    raise _unauthorized()


def _human_principal(token: str, db: Session) -> Principal:
    payload = verify_token(token)
    if payload is None:
        raise _unauthorized("Invalid or expired session")
    try:
        user_id = uuid.UUID(payload.user_id)
        org_id = uuid.UUID(payload.org_id)
    except (TypeError, ValueError) as exc:
        raise _unauthorized("Invalid session claims") from exc

    membership = (
        db.query(OrganizationMember)
        .join(User, User.id == OrganizationMember.user_id)
        .filter(
            OrganizationMember.user_id == user_id,
            OrganizationMember.org_id == org_id,
            User.is_active.is_(True),
        )
        .one_or_none()
    )
    if membership is None:
        raise _unauthorized("Session organization is no longer available")
    return Principal(
        actor_type="user",
        user_id=user_id,
        org_id=org_id,
        role=membership.role,
        scopes=("read", "write") if membership.role in ADMIN_ROLES else ("read",),
    )


def get_current_principal(
    request: Request,
    authorization: str = Header(default=""),
    db: Session = Depends(get_db),
) -> Principal:
    token, authenticated_with_cookie = _request_human_token(request, authorization)
    principal = _human_principal(token, db)
    request.state.principal = principal
    request.state.authenticated_with_cookie = authenticated_with_cookie
    return principal


def get_current_user(
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> User:
    if principal.actor_type != "user" or principal.user_id is None:
        raise _unauthorized("Human authentication required")
    user = db.get(User, principal.user_id)
    if user is None:
        raise _unauthorized("User not found")
    return user


def get_current_org(
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> Organization:
    if principal.actor_type != "user" or principal.user_id is None:
        raise _unauthorized("Human authentication required")
    org = db.get(Organization, principal.org_id)
    if org is None:
        raise _unauthorized("Organization not found")
    return org


def require_org_admin(
    principal: Principal = Depends(get_current_principal),
) -> Principal:
    if principal.actor_type != "user" or principal.user_id is None:
        raise _unauthorized("Human authentication required")
    if principal.role not in ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="Organization administrator role required")
    return principal


def get_agent_principal(
    request: Request,
    x_agent_sentinel_key: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> Principal:
    api_key = x_agent_sentinel_key or x_api_key
    if not api_key:
        raise _unauthorized("Missing agent API key")
    key_hash = hash_api_key(api_key)
    agent = db.query(Agent).filter(Agent.api_key_hash == key_hash).one_or_none()
    if agent is None:
        agent = db.query(Agent).filter(Agent.grace_period_api_key_hash == key_hash).one_or_none()
        if agent and (
            agent.grace_period_api_key_expires_at is None
            or _as_utc(agent.grace_period_api_key_expires_at) <= datetime.now(timezone.utc)
        ):
            agent = None
    if agent is None:
        raise _unauthorized("Invalid agent API key")
    if agent.status == "revoked":
        raise HTTPException(status_code=403, detail="Agent credentials are revoked")
    identity = agent.identity
    if identity is None or not identity.active:
        raise HTTPException(status_code=403, detail="Agent identity is not active")
    if identity.expires_at is not None and _as_utc(identity.expires_at) <= datetime.now(
        timezone.utc
    ):
        raise HTTPException(status_code=403, detail="Agent identity is expired")
    principal = Principal(
        actor_type="agent",
        org_id=agent.org_id,
        agent_id=agent.id,
        role="agent",
        scopes=("telemetry:write", "enforce:write", "memory:write", "mcp:assess"),
    )
    request.state.principal = principal
    return principal


def get_tenant_principal(
    request: Request,
    authorization: str = Header(default=""),
    x_agent_sentinel_key: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> Principal:
    bearer_token = _bearer_token(authorization)
    cookie_token = request.cookies.get(ACCESS_COOKIE, "")
    token = bearer_token or cookie_token
    if token:
        principal = _human_principal(token, db)
        request.state.principal = principal
        request.state.authenticated_with_cookie = bearer_token is None
        return principal
    return get_agent_principal(request, x_agent_sentinel_key, x_api_key, db)


def require_user_csrf(
    request: Request,
    principal: Principal = Depends(get_current_principal),
    x_csrf_token: str | None = Header(default=None),
) -> Principal:
    if principal.actor_type != "user" or principal.user_id is None:
        raise _unauthorized("Human authentication required")
    if not getattr(request.state, "authenticated_with_cookie", True):
        return principal
    cookie_token = request.cookies.get(CSRF_COOKIE)
    if (
        not cookie_token
        or not x_csrf_token
        or not secrets.compare_digest(cookie_token, x_csrf_token)
    ):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    return principal


def require_csrf(principal: Principal = Depends(require_user_csrf)) -> Principal:
    if principal.role not in ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="Organization administrator role required")
    return principal


def _set_session_cookies(response: Response, access_token: str, refresh_token: str) -> str:
    settings = get_settings()
    common = {
        "secure": settings.cookie_secure,
        "samesite": "lax",
        "domain": settings.cookie_domain,
        "path": "/",
    }
    response.set_cookie(
        ACCESS_COOKIE,
        access_token,
        httponly=True,
        max_age=settings.access_token_expire_minutes * 60,
        **common,
    )
    response.set_cookie(
        REFRESH_COOKIE,
        refresh_token,
        httponly=True,
        max_age=settings.refresh_token_expire_days * 86400,
        **common,
    )
    csrf_token = secrets.token_urlsafe(32)
    response.set_cookie(
        CSRF_COOKIE,
        csrf_token,
        httponly=False,
        max_age=settings.refresh_token_expire_days * 86400,
        **common,
    )
    return csrf_token


def _clear_session_cookies(response: Response) -> None:
    settings = get_settings()
    for name in (ACCESS_COOKIE, REFRESH_COOKIE, CSRF_COOKIE):
        response.delete_cookie(name, path="/", domain=settings.cookie_domain)


def _issue_tokens(
    db: Session, *, user: User, org: Organization, role: str
) -> tuple[str, str, RefreshSession]:
    settings = get_settings()
    session_id = uuid.uuid4()
    access_token = create_access_token(
        user_id=str(user.id), org_id=str(org.id), email=user.email, role=role
    )
    refresh_token = create_refresh_token(
        user_id=str(user.id), org_id=str(org.id), email=user.email, jti=str(session_id)
    )
    refresh_session = RefreshSession(
        id=session_id,
        user_id=user.id,
        org_id=org.id,
        token_hash=sha256_text(refresh_token),
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days),
    )
    db.add(refresh_session)
    return access_token, refresh_token, refresh_session


def _refresh_claims(token: str) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
    decoded = decode_refresh_token(token)
    if decoded is None:
        raise _unauthorized("Invalid refresh token")
    try:
        session_id = uuid.UUID(decoded["jti"])
        user_id = uuid.UUID(decoded["user_id"])
        org_id = uuid.UUID(decoded["org_id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise _unauthorized("Invalid refresh token claims") from exc
    if decoded.get("sub") != str(user_id):
        raise _unauthorized("Invalid refresh token claims")
    return session_id, user_id, org_id


def _revoke_refresh_descendants(db: Session, session: RefreshSession) -> None:
    now = utcnow()
    visited = {session.id}
    next_id = session.replaced_by_id
    while next_id is not None and next_id not in visited:
        visited.add(next_id)
        descendant = (
            db.query(RefreshSession)
            .filter(
                RefreshSession.id == next_id,
                RefreshSession.user_id == session.user_id,
            )
            .with_for_update()
            .one_or_none()
        )
        if descendant is None:
            break
        if descendant.revoked_at is None:
            descendant.revoked_at = now
        next_id = descendant.replaced_by_id


def _active_refresh_session(db: Session, token: str) -> tuple[RefreshSession, uuid.UUID, uuid.UUID]:
    session_id, user_id, org_id = _refresh_claims(token)
    stored = (
        db.query(RefreshSession)
        .filter(RefreshSession.id == session_id)
        .with_for_update()
        .one_or_none()
    )
    if (
        stored is None
        or stored.user_id != user_id
        or stored.org_id != org_id
        or not secrets.compare_digest(stored.token_hash, sha256_text(token))
    ):
        raise _unauthorized("Invalid refresh session")
    if stored.revoked_at is not None:
        if stored.replaced_by_id is not None:
            _revoke_refresh_descendants(db, stored)
            db.commit()
        raise _unauthorized("Refresh session is expired or revoked")
    if _as_utc(stored.expires_at) <= datetime.now(timezone.utc):
        raise _unauthorized("Refresh session is expired or revoked")
    return stored, user_id, org_id


def _auth_response(*, user: User, org: Organization, access_token: str, refresh_token: str) -> dict:
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": user,
        "organization": org,
    }


@router.post("/login", response_model=AuthTokenResponse)
def login(request: UserLogin, response: Response, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).one_or_none()
    if (
        user is None
        or not user.is_active
        or not verify_password(request.password, user.password_hash)
    ):
        raise _unauthorized("Invalid email or password")
    membership = (
        db.query(OrganizationMember)
        .filter(OrganizationMember.user_id == user.id)
        .order_by(OrganizationMember.created_at)
        .first()
    )
    if membership is None:
        raise HTTPException(status_code=403, detail="User has no organization membership")
    access_token, refresh_token, _ = _issue_tokens(
        db, user=user, org=membership.organization, role=membership.role
    )
    db.commit()
    _set_session_cookies(response, access_token, refresh_token)
    return _auth_response(
        user=user,
        org=membership.organization,
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.post("/register", response_model=AuthTokenResponse, status_code=status.HTTP_201_CREATED)
def register(request: UserRegister, response: Response, db: Session = Depends(get_db)):
    if not get_settings().allow_open_register:
        raise HTTPException(status_code=403, detail="Open registration is disabled")
    if db.query(User).filter(User.email == request.email).first():
        raise HTTPException(status_code=409, detail="Email already registered")

    user = User(email=request.email, password_hash=hash_password(request.password), is_active=True)
    db.add(user)
    db.flush()
    slug = request.org_name.lower().replace(" ", "-") + "-" + str(uuid.uuid4())[:8]
    org = Organization(name=request.org_name, slug=slug, owner_id=user.id)
    db.add(org)
    db.flush()
    membership = OrganizationMember(org_id=org.id, user_id=user.id, role="owner")
    db.add(membership)
    access_token, refresh_token, _ = _issue_tokens(db, user=user, org=org, role="owner")
    db.commit()
    db.refresh(user)
    db.refresh(org)
    _set_session_cookies(response, access_token, refresh_token)
    return _auth_response(
        user=user, org=org, access_token=access_token, refresh_token=refresh_token
    )


@router.get("/session", response_model=AuthSessionResponse)
def session(
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    user = db.get(User, principal.user_id)
    org = db.get(Organization, principal.org_id)
    if user is None or org is None:
        raise _unauthorized()
    return {"user": user, "organization": org, "role": principal.role}


@router.post("/switch-organization", response_model=AuthTokenResponse)
def switch_organization(
    payload: OrganizationSwitch,
    response: Response,
    principal: Principal = Depends(require_user_csrf),
    refresh_cookie: str | None = Cookie(default=None, alias=REFRESH_COOKIE),
    db: Session = Depends(get_db),
):
    old_session, refresh_user_id, refresh_org_id = _active_refresh_session(db, refresh_cookie or "")
    if refresh_user_id != principal.user_id or refresh_org_id != principal.org_id:
        raise _unauthorized("Refresh session does not match the current session")
    membership = (
        db.query(OrganizationMember)
        .filter(
            OrganizationMember.user_id == principal.user_id,
            OrganizationMember.org_id == payload.org_id,
        )
        .one_or_none()
    )
    user = db.get(User, principal.user_id)
    org = db.get(Organization, payload.org_id)
    if membership is None or user is None or org is None:
        raise HTTPException(status_code=404, detail="Organization membership not found")
    old_session.revoked_at = utcnow()
    access_token, refresh_token, new_session = _issue_tokens(
        db, user=user, org=org, role=membership.role
    )
    old_session.replaced_by_id = new_session.id
    db.commit()
    _set_session_cookies(response, access_token, refresh_token)
    return _auth_response(
        user=user, org=org, access_token=access_token, refresh_token=refresh_token
    )


@router.post("/refresh", response_model=AuthTokenResponse)
def refresh(
    payload: TokenRefresh,
    response: Response,
    refresh_cookie: str | None = Cookie(default=None, alias=REFRESH_COOKIE),
    db: Session = Depends(get_db),
):
    token = payload.refresh_token or refresh_cookie
    old_session, user_id, org_id = _active_refresh_session(db, token or "")

    membership = (
        db.query(OrganizationMember)
        .filter(
            OrganizationMember.user_id == user_id,
            OrganizationMember.org_id == org_id,
        )
        .one_or_none()
    )
    user = db.get(User, user_id)
    org = db.get(Organization, org_id)
    if membership is None or user is None or org is None or not user.is_active:
        raise _unauthorized("Refresh session membership is invalid")

    old_session.revoked_at = utcnow()
    access_token, refresh_token, new_session = _issue_tokens(
        db, user=user, org=org, role=membership.role
    )
    old_session.replaced_by_id = new_session.id
    db.commit()
    _set_session_cookies(response, access_token, refresh_token)
    return _auth_response(
        user=user, org=org, access_token=access_token, refresh_token=refresh_token
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    response: Response,
    refresh_cookie: str | None = Cookie(default=None, alias=REFRESH_COOKIE),
    db: Session = Depends(get_db),
):
    decoded = decode_refresh_token(refresh_cookie or "")
    if decoded and decoded.get("jti"):
        try:
            stored = db.get(RefreshSession, uuid.UUID(decoded["jti"]))
            if stored and stored.revoked_at is None:
                stored.revoked_at = utcnow()
                db.commit()
        except (TypeError, ValueError):
            pass
    _clear_session_cookies(response)
    response.status_code = status.HTTP_204_NO_CONTENT
