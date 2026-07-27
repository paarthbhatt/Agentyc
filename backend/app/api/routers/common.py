from __future__ import annotations

from uuid import UUID

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from app.api.auth import Principal
from app.models import Agent
from app.services.audit import record_audit


def _request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


def _agent_for_org(db: Session, agent_id: UUID, org_id: UUID) -> Agent:
    agent = db.query(Agent).filter(Agent.id == agent_id, Agent.org_id == org_id).one_or_none()
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


def _assert_agent(principal: Principal, agent_id: UUID) -> None:
    if principal.agent_id != agent_id:
        raise HTTPException(status_code=403, detail="Agent key does not match requested agent")


def _audit(
    db: Session,
    principal: Principal,
    request: Request,
    *,
    action: str,
    resource_type: str,
    resource_id: str,
    details: dict | None = None,
) -> None:
    record_audit(
        db,
        org_id=principal.org_id,
        user_id=principal.user_id,
        actor_type=principal.actor_type,
        actor_id=str(principal.user_id or principal.agent_id),
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        request_id=_request_id(request),
    )
