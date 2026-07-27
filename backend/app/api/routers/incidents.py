from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.api.auth import Principal, get_current_principal, require_csrf
from app.api.routers.common import _agent_for_org, _audit
from app.db.session import get_db
from app.models import AuditLog, Incident, TelemetryEvent
from app.schemas import (
    AuditLogRead,
    GraphResponse,
    IncidentRead,
    IncidentUpdate,
    TelemetryEventRead,
)
from app.services.audit import verify_audit_chain
from app.services.graph_service import graph_for_agent

router = APIRouter()


@router.get("/incidents", response_model=list[IncidentRead])
def list_incidents(
    status_filter: str | None = None,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> list[Incident]:
    query = db.query(Incident).filter(Incident.org_id == principal.org_id)
    if status_filter:
        query = query.filter(Incident.status == status_filter)
    return query.order_by(desc(Incident.created_at)).limit(200).all()


@router.get("/audit-logs", response_model=list[AuditLogRead])
def list_audit_logs(
    action_filter: str | None = None,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> list[AuditLog]:
    query = db.query(AuditLog).filter(AuditLog.org_id == principal.org_id)
    if action_filter:
        query = query.filter(AuditLog.action == action_filter)
    return query.order_by(desc(AuditLog.created_at)).limit(200).all()


@router.get("/audit-logs/integrity")
def audit_log_integrity(
    principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)
) -> dict[str, str | bool | None]:
    valid, invalid_record_id = verify_audit_chain(db, org_id=principal.org_id)
    return {"valid": valid, "invalid_record_id": invalid_record_id}


@router.patch("/incidents/{incident_id}", response_model=IncidentRead)
def update_incident(
    incident_id: UUID,
    payload: IncidentUpdate,
    request: Request,
    principal: Principal = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> Incident:
    incident = (
        db.query(Incident)
        .filter(Incident.id == incident_id, Incident.org_id == principal.org_id)
        .one_or_none()
    )
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    before = {"status": incident.status, "response_actions": incident.response_actions}
    if payload.status is not None:
        incident.status = payload.status
    if payload.response_actions is not None:
        incident.response_actions = payload.response_actions
    _audit(
        db,
        principal,
        request,
        action="incident.update",
        resource_type="incident",
        resource_id=str(incident.id),
        details={"before": before, "after": payload.model_dump(mode="json")},
    )
    db.commit()
    db.refresh(incident)
    return incident


@router.post("/incidents/{incident_id}/respond", response_model=IncidentRead)
def respond_to_incident(
    incident_id: UUID,
    action: str,
    request: Request,
    principal: Principal = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> Incident:
    incident = (
        db.query(Incident)
        .filter(Incident.id == incident_id, Incident.org_id == principal.org_id)
        .one_or_none()
    )
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident.response_actions = list(dict.fromkeys([*(incident.response_actions or []), action]))
    if action in {"close", "resolve"}:
        incident.status = "resolved"
    _audit(
        db,
        principal,
        request,
        action="incident.respond",
        resource_type="incident",
        resource_id=str(incident.id),
        details={"response": action},
    )
    db.commit()
    db.refresh(incident)
    return incident


def _timeline(db: Session, incident: Incident) -> list[TelemetryEvent]:
    return (
        db.query(TelemetryEvent)
        .filter(
            TelemetryEvent.org_id == incident.org_id,
            TelemetryEvent.agent_id == incident.agent_id,
            TelemetryEvent.session_id == incident.session_id,
        )
        .order_by(TelemetryEvent.occurred_at)
        .all()
    )


@router.get("/incidents/{incident_id}/timeline", response_model=list[TelemetryEventRead])
def incident_timeline(
    incident_id: UUID,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> list[TelemetryEvent]:
    incident = (
        db.query(Incident)
        .filter(Incident.id == incident_id, Incident.org_id == principal.org_id)
        .one_or_none()
    )
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _timeline(db, incident)


@router.get("/replay/incidents/{incident_id}")
def replay_incident(
    incident_id: UUID,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> dict:
    incident = (
        db.query(Incident)
        .filter(Incident.id == incident_id, Incident.org_id == principal.org_id)
        .one_or_none()
    )
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {
        "incident": IncidentRead.model_validate(incident).model_dump(mode="json"),
        "timeline": [
            TelemetryEventRead.model_validate(event).model_dump(mode="json")
            for event in _timeline(db, incident)
        ],
    }


@router.get("/replay/sessions/{session_id}", response_model=list[TelemetryEventRead])
def replay_session(
    session_id: str,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> list[TelemetryEvent]:
    return (
        db.query(TelemetryEvent)
        .filter(TelemetryEvent.org_id == principal.org_id, TelemetryEvent.session_id == session_id)
        .order_by(TelemetryEvent.occurred_at)
        .all()
    )


@router.get("/graph/agents/{agent_id}", response_model=GraphResponse)
def get_agent_graph(
    agent_id: UUID,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> GraphResponse:
    agent = _agent_for_org(db, agent_id, principal.org_id)
    events = (
        db.query(TelemetryEvent)
        .filter(TelemetryEvent.org_id == principal.org_id, TelemetryEvent.agent_id == agent_id)
        .order_by(TelemetryEvent.occurred_at)
        .limit(300)
        .all()
    )
    incidents = (
        db.query(Incident)
        .filter(Incident.org_id == principal.org_id, Incident.agent_id == agent_id)
        .order_by(Incident.created_at)
        .limit(100)
        .all()
    )
    return graph_for_agent(agent, events, incidents)


@router.get("/graph/incidents/{incident_id}", response_model=GraphResponse)
def get_incident_graph(
    incident_id: UUID,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> GraphResponse:
    incident = (
        db.query(Incident)
        .filter(Incident.id == incident_id, Incident.org_id == principal.org_id)
        .one_or_none()
    )
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    agent = _agent_for_org(db, incident.agent_id, principal.org_id)
    return graph_for_agent(agent, _timeline(db, incident), [incident])
