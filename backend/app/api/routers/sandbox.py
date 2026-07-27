from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.auth import Principal, get_current_principal, require_csrf
from app.api.routers.common import _audit
from app.db.session import get_db
from app.models import SandboxProfile
from app.schemas import SandboxProfileCreate, SandboxProfileRead

router = APIRouter()


@router.post(
    "/sandbox/profiles", response_model=SandboxProfileRead, status_code=status.HTTP_201_CREATED
)
def create_sandbox_profile(
    payload: SandboxProfileCreate,
    request: Request,
    principal: Principal = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> SandboxProfile:
    if (
        db.query(SandboxProfile)
        .filter(SandboxProfile.org_id == principal.org_id, SandboxProfile.name == payload.name)
        .first()
    ):
        raise HTTPException(status_code=409, detail="Sandbox profile already exists")
    profile = SandboxProfile(org_id=principal.org_id, **payload.model_dump())
    db.add(profile)
    db.flush()
    _audit(
        db,
        principal,
        request,
        action="sandbox_profile.create",
        resource_type="sandbox_profile",
        resource_id=str(profile.id),
        details={"enforcement_status": profile.enforcement_status},
    )
    db.commit()
    db.refresh(profile)
    return profile


@router.get("/sandbox/profiles", response_model=list[SandboxProfileRead])
def list_sandbox_profiles(
    principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)
) -> list[SandboxProfile]:
    return (
        db.query(SandboxProfile)
        .filter(SandboxProfile.org_id == principal.org_id)
        .order_by(SandboxProfile.name)
        .all()
    )
