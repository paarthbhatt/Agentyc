from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.auth import Principal, get_current_principal
from app.db.session import get_db
from app.models import Agent, Incident, MemoryObject, TelemetryEvent
from app.schemas import DashboardSummary

router = APIRouter()


@router.get("/dashboard/summary", response_model=DashboardSummary)
def dashboard_summary(
    principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)
) -> DashboardSummary:
    org_id = principal.org_id
    agents = db.query(Agent).filter(Agent.org_id == org_id)
    active_agents = agents.filter(Agent.status == "active").count()
    agent_count = agents.count()
    global_risk = (
        int(db.query(func.avg(Agent.risk_score)).filter(Agent.org_id == org_id).scalar() or 0)
        if agent_count
        else 0
    )
    return DashboardSummary(
        active_agents=active_agents,
        global_risk_score=global_risk,
        ongoing_attacks=db.query(Incident)
        .filter(Incident.org_id == org_id, Incident.status == "open")
        .count(),
        blocked_actions=db.query(TelemetryEvent)
        .filter(TelemetryEvent.org_id == org_id, TelemetryEvent.event_type == "tool.blocked")
        .count(),
        prompt_injection_attempts=db.query(Incident)
        .filter(Incident.org_id == org_id, Incident.category == "prompt_injection")
        .count(),
        memory_poisoning_alerts=db.query(MemoryObject)
        .filter(MemoryObject.org_id == org_id, MemoryObject.security_status == "quarantined")
        .count(),
        trust_violations=db.query(TelemetryEvent)
        .filter(TelemetryEvent.org_id == org_id, TelemetryEvent.event_type == "trust.violation")
        .count(),
        identity_violations=db.query(Incident)
        .filter(Incident.org_id == org_id, Incident.category == "identity_violation")
        .count(),
    )
