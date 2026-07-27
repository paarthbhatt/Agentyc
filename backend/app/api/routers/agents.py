from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.api.auth import Principal, get_current_principal, require_csrf
from app.api.routers.common import _agent_for_org, _audit
from app.core.security import generate_api_key, hash_api_key
from app.db.session import get_db
from app.models import Agent, AgentIdentity
from app.schemas import (
    AgentCreate,
    AgentCreateResponse,
    AgentRead,
    IdentityRead,
    IdentityUpsert,
)
from app.services.identity import default_permissions_for_role

router = APIRouter()


@router.post("/agents", response_model=AgentCreateResponse, status_code=status.HTTP_201_CREATED)
def create_agent(
    payload: AgentCreate,
    request: Request,
    principal: Principal = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> AgentCreateResponse:
    existing = (
        db.query(Agent)
        .filter(Agent.org_id == principal.org_id, Agent.name == payload.name)
        .one_or_none()
    )
    if existing:
        raise HTTPException(status_code=409, detail="Agent name already exists")
    api_key = generate_api_key()
    agent = Agent(
        org_id=principal.org_id,
        name=payload.name,
        framework=payload.framework,
        owner=payload.owner,
        environment=payload.environment,
        api_key_hash=hash_api_key(api_key),
    )
    db.add(agent)
    db.flush()
    db.add(
        AgentIdentity(
            agent_id=agent.id,
            role=payload.role,
            permissions=payload.permissions or default_permissions_for_role(payload.role),
        )
    )
    _audit(
        db,
        principal,
        request,
        action="agent.create",
        resource_type="agent",
        resource_id=str(agent.id),
    )
    db.commit()
    db.refresh(agent)
    return AgentCreateResponse(agent=AgentRead.model_validate(agent), api_key=api_key)


@router.get("/agents", response_model=list[AgentRead])
def list_agents(
    principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)
) -> list[Agent]:
    return (
        db.query(Agent)
        .filter(Agent.org_id == principal.org_id)
        .order_by(desc(Agent.created_at))
        .all()
    )


@router.get("/agents/{agent_id}", response_model=AgentRead)
def get_agent(
    agent_id: UUID,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> Agent:
    return _agent_for_org(db, agent_id, principal.org_id)


@router.post("/agents/{agent_id}/rotate-key")
def rotate_agent_key(
    agent_id: UUID,
    request: Request,
    principal: Principal = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    agent = _agent_for_org(db, agent_id, principal.org_id)
    new_api_key = generate_api_key()
    agent.grace_period_api_key_hash = agent.api_key_hash
    agent.grace_period_api_key_expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    agent.api_key_hash = hash_api_key(new_api_key)
    _audit(
        db,
        principal,
        request,
        action="agent.key.rotate",
        resource_type="agent",
        resource_id=str(agent.id),
    )
    db.commit()
    return {
        "message": "Key rotated; the previous key expires in five minutes",
        "new_api_key": new_api_key,
    }


@router.post("/agents/{agent_id}/revoke-key", status_code=status.HTTP_204_NO_CONTENT)
def revoke_agent_key(
    agent_id: UUID,
    request: Request,
    principal: Principal = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> None:
    agent = _agent_for_org(db, agent_id, principal.org_id)
    agent.status = "revoked"
    agent.api_key_hash = hash_api_key(generate_api_key())
    agent.grace_period_api_key_hash = None
    agent.grace_period_api_key_expires_at = None
    _audit(
        db,
        principal,
        request,
        action="agent.key.revoke",
        resource_type="agent",
        resource_id=str(agent.id),
    )
    db.commit()


@router.get("/agents/{agent_id}/identity", response_model=IdentityRead)
def get_identity(
    agent_id: UUID,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> AgentIdentity:
    agent = _agent_for_org(db, agent_id, principal.org_id)
    if agent.identity is None:
        raise HTTPException(status_code=404, detail="Identity not found")
    return agent.identity


@router.put("/agents/{agent_id}/identity", response_model=IdentityRead)
def upsert_identity(
    agent_id: UUID,
    payload: IdentityUpsert,
    request: Request,
    principal: Principal = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> AgentIdentity:
    agent = _agent_for_org(db, agent_id, principal.org_id)
    identity = agent.identity or AgentIdentity(agent_id=agent.id)
    if agent.identity is None:
        db.add(identity)
    before = {"role": identity.role, "active": identity.active}
    identity.role = payload.role
    identity.permissions = payload.permissions
    identity.expires_at = payload.expires_at
    identity.active = payload.active
    _audit(
        db,
        principal,
        request,
        action="agent.identity.update",
        resource_type="agent_identity",
        resource_id=str(agent.id),
        details={"before": before, "after": {"role": payload.role, "active": payload.active}},
    )
    db.commit()
    db.refresh(identity)
    return identity
