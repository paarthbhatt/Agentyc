from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.api.auth import Principal, get_current_principal, require_csrf
from app.api.routers.common import _audit
from app.db.session import get_db
from app.models import PolicyPack
from app.schemas import PolicyPackCreate, PolicyPackRead

router = APIRouter()


@router.get("/policies", response_model=list[PolicyPackRead])
def list_policies(
    principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)
) -> list[PolicyPack]:
    return (
        db.query(PolicyPack)
        .filter(PolicyPack.org_id == principal.org_id)
        .order_by(desc(PolicyPack.created_at))
        .limit(50)
        .all()
    )


@router.post("/policies", response_model=PolicyPackRead, status_code=status.HTTP_201_CREATED)
def create_policy(
    payload: PolicyPackCreate,
    request: Request,
    principal: Principal = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> PolicyPack:
    if (
        db.query(PolicyPack)
        .filter(PolicyPack.org_id == principal.org_id, PolicyPack.name == payload.name)
        .first()
    ):
        raise HTTPException(status_code=409, detail="Policy name already exists")
    policy = PolicyPack(org_id=principal.org_id, **payload.model_dump())
    db.add(policy)
    db.flush()
    _audit(
        db,
        principal,
        request,
        action="policy.create",
        resource_type="policy",
        resource_id=str(policy.id),
        details={"version": policy.version},
    )
    db.commit()
    db.refresh(policy)
    return policy


@router.patch("/policies/{policy_id}", response_model=PolicyPackRead)
def update_policy(
    policy_id: UUID,
    payload: PolicyPackCreate,
    request: Request,
    principal: Principal = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> PolicyPack:
    policy = (
        db.query(PolicyPack)
        .filter(PolicyPack.id == policy_id, PolicyPack.org_id == principal.org_id)
        .one_or_none()
    )
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    old_version = policy.version
    for key, value in payload.model_dump().items():
        setattr(policy, key, value)
    policy.version += 1
    _audit(
        db,
        principal,
        request,
        action="policy.update",
        resource_type="policy",
        resource_id=str(policy.id),
        details={"old_version": old_version, "new_version": policy.version},
    )
    db.commit()
    db.refresh(policy)
    return policy
