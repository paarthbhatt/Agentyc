from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, status
from sqlalchemy import desc
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.auth import Principal, get_agent_principal, get_current_principal
from app.api.routers.common import _agent_for_org, _assert_agent
from app.db.session import get_db
from app.models import TelemetryEvent
from app.schemas import TelemetryEventCreate, TelemetryEventRead
from app.services.behavior import update_behavior_baseline
from app.services.outbox import queue_integration

router = APIRouter()


@router.post(
    "/telemetry/events", response_model=TelemetryEventRead, status_code=status.HTTP_201_CREATED
)
def create_event(
    payload: TelemetryEventCreate,
    principal: Principal = Depends(get_agent_principal),
    db: Session = Depends(get_db),
) -> TelemetryEvent:
    _assert_agent(principal, payload.agent_id)
    agent = _agent_for_org(db, payload.agent_id, principal.org_id)
    if payload.client_event_id:
        existing = (
            db.query(TelemetryEvent)
            .filter(
                TelemetryEvent.org_id == principal.org_id,
                TelemetryEvent.agent_id == agent.id,
                TelemetryEvent.client_event_id == payload.client_event_id,
            )
            .one_or_none()
        )
        if existing:
            return existing
    event = TelemetryEvent(org_id=principal.org_id, **payload.model_dump())
    db.add(event)
    db.flush()
    update_behavior_baseline(db, event)
    agent.risk_score = max(agent.risk_score, payload.risk_score)
    agent.trust_level = min(agent.trust_level, payload.trust_score)
    queue_integration(
        db,
        org_id=principal.org_id,
        event_type="telemetry.created",
        aggregate_type="telemetry",
        aggregate_id=str(event.id),
    )
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        if payload.client_event_id:
            existing = (
                db.query(TelemetryEvent)
                .filter(
                    TelemetryEvent.org_id == principal.org_id,
                    TelemetryEvent.agent_id == agent.id,
                    TelemetryEvent.client_event_id == payload.client_event_id,
                )
                .one_or_none()
            )
            if existing:
                return existing
        raise
    db.refresh(event)
    return event


@router.get("/agents/{agent_id}/events", response_model=list[TelemetryEventRead])
def list_agent_events(
    agent_id: UUID,
    limit: int = 100,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> list[TelemetryEvent]:
    _agent_for_org(db, agent_id, principal.org_id)
    return (
        db.query(TelemetryEvent)
        .filter(TelemetryEvent.org_id == principal.org_id, TelemetryEvent.agent_id == agent_id)
        .order_by(desc(TelemetryEvent.occurred_at))
        .limit(max(1, min(limit, 500)))
        .all()
    )
