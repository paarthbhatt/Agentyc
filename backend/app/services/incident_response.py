from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import Agent, Incident, TelemetryEvent, Tool
from app.services.outbox import queue_integration


def recommended_actions(category: str, severity: str) -> list[str]:
    actions = ["create_incident"]
    if category in {
        "prompt_injection",
        "intent_mismatch",
        "tool_abuse",
        "data_exfiltration",
        "mcp_tool_poisoning",
    }:
        actions.append("block_tool")
    if category == "memory_poisoning":
        actions.append("isolate_memory")
    if severity in {"critical", "high"}:
        actions.append("require_human_approval")
    if severity == "critical":
        actions.extend(["revoke_temporary_credentials", "suspend_agent"])
    return list(dict.fromkeys(actions))


def create_incident(
    db: Session,
    *,
    agent: Agent,
    session_id: str,
    title: str,
    category: str,
    severity: str,
    root_cause: str,
    evidence: dict,
    response_actions: list[str] | None = None,
) -> Incident:
    incident = Incident(
        org_id=agent.org_id,
        agent_id=agent.id,
        session_id=session_id,
        title=title,
        category=category,
        severity=severity,
        root_cause=root_cause,
        evidence=evidence,
        response_actions=response_actions or recommended_actions(category, severity),
    )
    db.add(incident)
    db.flush()
    queue_integration(
        db,
        org_id=agent.org_id,
        event_type="incident.created",
        aggregate_type="incident",
        aggregate_id=str(incident.id),
    )

    event = TelemetryEvent(
        org_id=agent.org_id,
        agent_id=agent.id,
        session_id=session_id,
        event_type="incident.created",
        severity=severity,
        payload={"title": title, "category": category, "root_cause": root_cause},
        trust_score=evidence.get("trust_score", 30),
        risk_score=evidence.get("risk_score", 80),
    )
    db.add(event)

    if severity == "critical":
        agent.status = "suspended"
    agent.risk_score = max(agent.risk_score, evidence.get("risk_score", agent.risk_score))
    agent.trust_level = min(agent.trust_level, evidence.get("trust_score", agent.trust_level))

    tool_name = evidence.get("tool_name")
    if tool_name:
        tool = (
            db.query(Tool).filter(Tool.org_id == agent.org_id, Tool.name == tool_name).one_or_none()
        )
        if tool:
            tool.incident_count += 1
            if severity in {"critical", "high"}:
                tool.status = "suspicious"
                tool.trust_score = max(0, tool.trust_score - 15)

    db.flush()
    return incident
