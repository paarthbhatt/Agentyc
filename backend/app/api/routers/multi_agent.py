from __future__ import annotations

from fastapi import APIRouter, Depends, status
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.api.auth import Principal, get_agent_principal, get_current_principal
from app.api.routers.common import _agent_for_org, _assert_agent
from app.db.session import get_db
from app.models import MultiAgentMessage, TelemetryEvent
from app.schemas import MultiAgentMessageCreate, MultiAgentMessageRead
from app.services.multi_agent_security import evaluate_delegation

router = APIRouter()


@router.post(
    "/multi-agent/messages",
    response_model=MultiAgentMessageRead,
    status_code=status.HTTP_201_CREATED,
)
def create_multi_agent_message(
    payload: MultiAgentMessageCreate,
    principal: Principal = Depends(get_agent_principal),
    db: Session = Depends(get_db),
) -> MultiAgentMessage:
    _assert_agent(principal, payload.source_agent_id)
    source = _agent_for_org(db, payload.source_agent_id, principal.org_id)
    target = _agent_for_org(db, payload.target_agent_id, principal.org_id)
    trust, risk, decision, reasons = evaluate_delegation(
        source=source,
        target=target,
        task=payload.task,
        requested_permissions=payload.requested_permissions,
    )
    message = MultiAgentMessage(
        org_id=principal.org_id,
        source_agent_id=source.id,
        target_agent_id=target.id,
        session_id=payload.session_id,
        task=payload.task,
        requested_permissions=payload.requested_permissions,
        trust_inheritance_score=trust,
        risk_score=risk,
        decision=decision,
        reasons=reasons,
    )
    db.add(message)
    db.add(
        TelemetryEvent(
            org_id=principal.org_id,
            agent_id=source.id,
            session_id=payload.session_id,
            event_type="agent.delegation." + decision,
            severity="critical"
            if decision == "block"
            else "high"
            if decision == "challenge"
            else "info",
            payload={
                "target_agent_id": str(target.id),
                "task": payload.task,
                "requested_permissions": payload.requested_permissions,
                "reasons": reasons,
            },
            trust_score=trust,
            risk_score=risk,
        )
    )
    if decision == "block":
        source.risk_score = max(source.risk_score, risk)
        target.risk_score = max(target.risk_score, risk)
    db.commit()
    db.refresh(message)
    return message


@router.get("/multi-agent/messages", response_model=list[MultiAgentMessageRead])
def list_multi_agent_messages(
    principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)
) -> list[MultiAgentMessage]:
    return (
        db.query(MultiAgentMessage)
        .filter(MultiAgentMessage.org_id == principal.org_id)
        .order_by(desc(MultiAgentMessage.created_at))
        .limit(200)
        .all()
    )
