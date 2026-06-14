from __future__ import annotations

import asyncio
import json
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import generate_api_key, hash_api_key, sha256_text, verify_api_key
from app.db.session import SessionLocal, get_db
from app.models import (
    Agent,
    AgentIdentity,
    BehaviorBaseline,
    Incident,
    MCPAssessment,
    MemoryObject,
    MultiAgentMessage,
    RedTeamScenario,
    SandboxProfile,
    TelemetryEvent,
    ThreatIntelIndicator,
    Tool,
)
from app.schemas import (
    AgentCreate,
    AgentCreateResponse,
    AgentRead,
    DashboardSummary,
    EnforcementDecision,
    EnforcementRequest,
    GraphResponse,
    IdentityRead,
    IdentityUpsert,
    IncidentRead,
    IncidentUpdate,
    MCPAssessmentCreate,
    MCPAssessmentRead,
    MemoryCreate,
    MemoryRead,
    MultiAgentMessageCreate,
    MultiAgentMessageRead,
    RedTeamGenerateRequest,
    RedTeamScenarioRead,
    SandboxProfileCreate,
    SandboxProfileRead,
    TelemetryEventCreate,
    TelemetryEventRead,
    ThreatIntelCreate,
    ThreatIntelRead,
    ToolCreate,
    ToolRead,
    BehaviorBaselineRead,
)
from app.services.detection import MEMORY_POISONING_PATTERNS, PROMPT_INJECTION_PATTERNS
from app.services.behavior import update_behavior_baseline
from app.services.firewall import evaluate_and_record
from app.services.graph_service import graph_for_agent
from app.services.identity import default_permissions_for_role
from app.services.mcp_security import assess_mcp_tool
from app.services.memory_security import create_memory_object
from app.services.multi_agent_security import evaluate_delegation
from app.services.red_team import generate_red_team_scenarios

router = APIRouter()
settings = get_settings()


def require_admin_key(api_key: str | None) -> None:
    if settings.admin_api_key and api_key != settings.admin_api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing admin API key")


def require_agent_key(agent: Agent, api_key: str | None) -> None:
    if api_key is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing agent API key")
    if not verify_api_key(api_key, agent.api_key_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid agent API key")


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "agent-sentinel"}


@router.post("/agents", response_model=AgentCreateResponse, status_code=status.HTTP_201_CREATED)
def create_agent(payload: AgentCreate, x_admin_api_key: str | None = Header(default=None), db: Session = Depends(get_db)) -> AgentCreateResponse:
    require_admin_key(x_admin_api_key)
    api_key = generate_api_key()
    permissions = payload.permissions or default_permissions_for_role(payload.role)
    # Ensure a default organization exists
    from app.models import Organization
    import uuid
    org = db.query(Organization).filter(Organization.slug == "demo-org").one_or_none()
    if not org:
        org = Organization(name="Demo Organization", slug="demo-org", owner_id=uuid.uuid4())
        db.add(org)
        db.flush()
    agent = Agent(
        org_id=org.id,
        name=payload.name,
        framework=payload.framework,
        owner=payload.owner,
        environment=payload.environment,
        api_key_hash=hash_api_key(api_key),
    )
    db.add(agent)
    db.flush()
    db.add(AgentIdentity(agent_id=agent.id, role=payload.role, permissions=permissions))
    db.commit()
    db.refresh(agent)
    return AgentCreateResponse(agent=AgentRead.model_validate(agent), api_key=api_key)


@router.get("/agents", response_model=list[AgentRead])
def list_agents(db: Session = Depends(get_db)) -> list[Agent]:
    return db.query(Agent).order_by(desc(Agent.created_at)).all()


@router.get("/agents/{agent_id}", response_model=AgentRead)
def get_agent(agent_id: UUID, db: Session = Depends(get_db)) -> Agent:
    agent = db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


@router.get("/agents/{agent_id}/identity", response_model=IdentityRead)
def get_identity(agent_id: UUID, db: Session = Depends(get_db)) -> AgentIdentity:
    identity = db.query(AgentIdentity).filter(AgentIdentity.agent_id == agent_id).one_or_none()
    if identity is None:
        raise HTTPException(status_code=404, detail="Identity not found")
    return identity


@router.put("/agents/{agent_id}/identity", response_model=IdentityRead)
def upsert_identity(agent_id: UUID, payload: IdentityUpsert, x_admin_api_key: str | None = Header(default=None), db: Session = Depends(get_db)) -> AgentIdentity:
    require_admin_key(x_admin_api_key)
    agent = db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    identity = db.query(AgentIdentity).filter(AgentIdentity.agent_id == agent_id).one_or_none()
    if identity is None:
        identity = AgentIdentity(agent_id=agent_id)
        db.add(identity)
    identity.role = payload.role
    identity.permissions = payload.permissions
    identity.expires_at = payload.expires_at
    identity.active = payload.active
    db.commit()
    db.refresh(identity)
    return identity


@router.post("/telemetry/events", response_model=TelemetryEventRead, status_code=status.HTTP_201_CREATED)
def create_event(payload: TelemetryEventCreate, x_agent_sentinel_key: str | None = Header(default=None), db: Session = Depends(get_db)) -> TelemetryEvent:
    agent = db.get(Agent, payload.agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    require_agent_key(agent, x_agent_sentinel_key)
    event = TelemetryEvent(**payload.model_dump())
    db.add(event)
    db.flush()
    update_behavior_baseline(db, event)
    agent.risk_score = max(agent.risk_score, payload.risk_score)
    agent.trust_level = min(agent.trust_level, payload.trust_score)
    db.commit()
    db.refresh(event)
    return event


@router.get("/agents/{agent_id}/events", response_model=list[TelemetryEventRead])
def list_agent_events(agent_id: UUID, limit: int = 100, db: Session = Depends(get_db)) -> list[TelemetryEvent]:
    return (
        db.query(TelemetryEvent)
        .filter(TelemetryEvent.agent_id == agent_id)
        .order_by(desc(TelemetryEvent.occurred_at))
        .limit(min(limit, 500))
        .all()
    )


@router.post("/enforce/action", response_model=EnforcementDecision)
def enforce_action(payload: EnforcementRequest, x_agent_sentinel_key: str | None = Header(default=None), db: Session = Depends(get_db)) -> EnforcementDecision:
    agent = db.get(Agent, payload.agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    require_agent_key(agent, x_agent_sentinel_key)
    try:
        return evaluate_and_record(db, payload)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/tools", response_model=list[ToolRead])
def list_tools(db: Session = Depends(get_db)) -> list[Tool]:
    return db.query(Tool).order_by(Tool.name).all()


@router.post("/tools", response_model=ToolRead, status_code=status.HTTP_201_CREATED)
def create_tool(payload: ToolCreate, x_admin_api_key: str | None = Header(default=None), db: Session = Depends(get_db)) -> Tool:
    require_admin_key(x_admin_api_key)
    existing = db.query(Tool).filter(Tool.name == payload.name).one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="Tool already exists")
    tool = Tool(**payload.model_dump())
    db.add(tool)
    db.commit()
    db.refresh(tool)
    return tool


@router.patch("/tools/{tool_id}", response_model=ToolRead)
def update_tool(tool_id: UUID, payload: ToolCreate, x_admin_api_key: str | None = Header(default=None), db: Session = Depends(get_db)) -> Tool:
    require_admin_key(x_admin_api_key)
    tool = db.get(Tool, tool_id)
    if tool is None:
        raise HTTPException(status_code=404, detail="Tool not found")
    for key, value in payload.model_dump().items():
        setattr(tool, key, value)
    db.commit()
    db.refresh(tool)
    return tool


@router.post("/memory", response_model=MemoryRead, status_code=status.HTTP_201_CREATED)
def create_memory(payload: MemoryCreate, x_agent_sentinel_key: str | None = Header(default=None), db: Session = Depends(get_db)) -> MemoryObject:
    agent = db.get(Agent, payload.agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    require_agent_key(agent, x_agent_sentinel_key)
    return create_memory_object(db, agent_id=payload.agent_id, source=payload.source, content=payload.content)


@router.get("/memory", response_model=list[MemoryRead])
def list_memory(agent_id: UUID | None = None, db: Session = Depends(get_db)) -> list[MemoryObject]:
    query = db.query(MemoryObject)
    if agent_id:
        query = query.filter(MemoryObject.agent_id == agent_id)
    return query.order_by(desc(MemoryObject.modified_at)).limit(200).all()


@router.get("/incidents", response_model=list[IncidentRead])
def list_incidents(status_filter: str | None = None, db: Session = Depends(get_db)) -> list[Incident]:
    query = db.query(Incident)
    if status_filter:
        query = query.filter(Incident.status == status_filter)
    return query.order_by(desc(Incident.created_at)).limit(200).all()


@router.get("/incidents/{incident_id}", response_model=IncidentRead)
def get_incident(incident_id: UUID, db: Session = Depends(get_db)) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.patch("/incidents/{incident_id}", response_model=IncidentRead)
def update_incident(incident_id: UUID, payload: IncidentUpdate, db: Session = Depends(get_db)) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    if payload.status is not None:
        incident.status = payload.status
    if payload.response_actions is not None:
        incident.response_actions = payload.response_actions
    db.commit()
    db.refresh(incident)
    return incident


@router.post("/incidents/{incident_id}/respond", response_model=IncidentRead)
def respond_to_incident(incident_id: UUID, action: str, db: Session = Depends(get_db)) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    actions = list(incident.response_actions or [])
    actions.append(action)
    incident.response_actions = list(dict.fromkeys(actions))
    if action in {"close", "resolve"}:
        incident.status = "resolved"
    db.commit()
    db.refresh(incident)
    return incident


@router.get("/incidents/{incident_id}/timeline", response_model=list[TelemetryEventRead])
def incident_timeline(incident_id: UUID, db: Session = Depends(get_db)) -> list[TelemetryEvent]:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return (
        db.query(TelemetryEvent)
        .filter(TelemetryEvent.agent_id == incident.agent_id, TelemetryEvent.session_id == incident.session_id)
        .order_by(TelemetryEvent.occurred_at)
        .all()
    )


@router.get("/replay/incidents/{incident_id}")
def replay_incident(incident_id: UUID, db: Session = Depends(get_db)) -> dict:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    events = incident_timeline(incident_id, db)
    return {
        "incident": IncidentRead.model_validate(incident).model_dump(mode="json"),
        "timeline": [TelemetryEventRead.model_validate(event).model_dump(mode="json") for event in events],
    }


@router.get("/replay/sessions/{session_id}", response_model=list[TelemetryEventRead])
def replay_session(session_id: str, db: Session = Depends(get_db)) -> list[TelemetryEvent]:
    return db.query(TelemetryEvent).filter(TelemetryEvent.session_id == session_id).order_by(TelemetryEvent.occurred_at).all()


@router.get("/graph/agents/{agent_id}", response_model=GraphResponse)
def get_agent_graph(agent_id: UUID, db: Session = Depends(get_db)) -> GraphResponse:
    agent = db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    events = db.query(TelemetryEvent).filter(TelemetryEvent.agent_id == agent_id).order_by(TelemetryEvent.occurred_at).limit(300).all()
    incidents = db.query(Incident).filter(Incident.agent_id == agent_id).order_by(Incident.created_at).limit(100).all()
    return graph_for_agent(agent, events, incidents)


@router.get("/graph/incidents/{incident_id}", response_model=GraphResponse)
def get_incident_graph(incident_id: UUID, db: Session = Depends(get_db)) -> GraphResponse:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    agent = db.get(Agent, incident.agent_id)
    events = db.query(TelemetryEvent).filter(TelemetryEvent.agent_id == incident.agent_id, TelemetryEvent.session_id == incident.session_id).order_by(TelemetryEvent.occurred_at).all()
    return graph_for_agent(agent, events, [incident])


@router.get("/dashboard/summary", response_model=DashboardSummary)
def dashboard_summary(db: Session = Depends(get_db)) -> DashboardSummary:
    active_agents = db.query(Agent).filter(Agent.status == "active").count()
    agent_count = db.query(Agent).count()
    global_risk = int(db.query(func.avg(Agent.risk_score)).scalar() or 0) if agent_count else 0
    ongoing_attacks = db.query(Incident).filter(Incident.status == "open").count()
    blocked_actions = db.query(TelemetryEvent).filter(TelemetryEvent.event_type == "tool.blocked").count()
    prompt_injection = db.query(Incident).filter(Incident.category == "prompt_injection").count()
    memory_poisoning = db.query(MemoryObject).filter(MemoryObject.security_status == "quarantined").count()
    trust_violations = db.query(TelemetryEvent).filter(TelemetryEvent.event_type == "trust.violation").count()
    identity_violations = db.query(Incident).filter(Incident.category == "identity_violation").count()
    return DashboardSummary(
        active_agents=active_agents,
        global_risk_score=global_risk,
        ongoing_attacks=ongoing_attacks,
        blocked_actions=blocked_actions,
        prompt_injection_attempts=prompt_injection,
        memory_poisoning_alerts=memory_poisoning,
        trust_violations=trust_violations,
        identity_violations=identity_violations,
    )


@router.get("/policies")
def list_policies() -> dict:
    return {
        "version": "mvp-1",
        "thresholds": {
            "block_risk_gte": 85,
            "challenge_risk_gte": 70,
            "block_intent_match_lt": 35,
            "block_low_tool_trust_sensitive_lt": 30,
        },
        "fail_mode": "fail_closed_for_high_risk",
    }


@router.get("/threats")
def list_threats() -> dict:
    return {
        "prompt_injection_patterns": sorted(PROMPT_INJECTION_PATTERNS.keys()),
        "memory_poisoning_patterns": sorted(MEMORY_POISONING_PATTERNS.keys()),
        "mcp_security": ["malicious_tool_description", "hidden_instructions", "broad_filesystem_access", "unsigned_server"],
    }


@router.get("/risk/agents")
def agent_risk(db: Session = Depends(get_db)) -> list[dict]:
    agents = db.query(Agent).order_by(desc(Agent.risk_score)).limit(50).all()
    return [{"id": str(agent.id), "name": agent.name, "risk_score": agent.risk_score, "trust_level": agent.trust_level, "status": agent.status} for agent in agents]


@router.get("/trust/tools")
def tool_trust(db: Session = Depends(get_db)) -> list[dict]:
    tools = db.query(Tool).order_by(Tool.trust_score).all()
    return [{"id": str(tool.id), "name": tool.name, "type": tool.type, "trust_score": tool.trust_score, "status": tool.status, "incident_count": tool.incident_count} for tool in tools]


@router.get("/telemetry/stream")
def telemetry_stream(agent_id: UUID | None = None, poll_seconds: float = 1.5) -> StreamingResponse:
    async def event_generator():
        last_seen = None
        while True:
            db = SessionLocal()
            try:
                query = db.query(TelemetryEvent)
                if agent_id:
                    query = query.filter(TelemetryEvent.agent_id == agent_id)
                if last_seen:
                    query = query.filter(TelemetryEvent.occurred_at > last_seen)
                events = query.order_by(TelemetryEvent.occurred_at).limit(50).all()
                for event in events:
                    last_seen = event.occurred_at
                    payload = TelemetryEventRead.model_validate(event).model_dump(mode="json")
                    yield "data: " + json.dumps(payload) + "\n\n"
            finally:
                db.close()
            await asyncio.sleep(max(0.5, min(poll_seconds, 10)))

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.post("/mcp/assess", response_model=MCPAssessmentRead, status_code=status.HTTP_201_CREATED)
def assess_mcp(payload: MCPAssessmentCreate, db: Session = Depends(get_db)) -> MCPAssessment:
    risk_score, trust_score, verdict, findings = assess_mcp_tool(
        description=payload.description,
        declared_capabilities=payload.declared_capabilities,
        signed=payload.signed,
        pinned_version=payload.pinned_version,
    )
    assessment = MCPAssessment(
        server_name=payload.server_name,
        tool_name=payload.tool_name,
        description_hash=sha256_text(payload.description),
        risk_score=risk_score,
        trust_score=trust_score,
        verdict=verdict,
        findings=findings,
    )
    db.add(assessment)
    tool = db.query(Tool).filter(Tool.name == payload.tool_name).one_or_none()
    if tool:
        tool.trust_score = min(tool.trust_score, trust_score)
        if verdict in {"blocked", "suspicious"}:
            tool.status = verdict
            tool.known_risks = list(dict.fromkeys([*(tool.known_risks or []), *findings]))
    db.commit()
    db.refresh(assessment)
    return assessment


@router.get("/mcp/assessments", response_model=list[MCPAssessmentRead])
def list_mcp_assessments(db: Session = Depends(get_db)) -> list[MCPAssessment]:
    return db.query(MCPAssessment).order_by(desc(MCPAssessment.created_at)).limit(200).all()


@router.post("/multi-agent/messages", response_model=MultiAgentMessageRead, status_code=status.HTTP_201_CREATED)
def create_multi_agent_message(payload: MultiAgentMessageCreate, db: Session = Depends(get_db)) -> MultiAgentMessage:
    source = db.get(Agent, payload.source_agent_id)
    target = db.get(Agent, payload.target_agent_id)
    if source is None or target is None:
        raise HTTPException(status_code=404, detail="Source or target agent not found")
    trust, risk, decision, reasons = evaluate_delegation(
        source=source,
        target=target,
        task=payload.task,
        requested_permissions=payload.requested_permissions,
    )
    message = MultiAgentMessage(
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
            agent_id=source.id,
            session_id=payload.session_id,
            event_type="agent.delegation." + decision,
            severity="critical" if decision == "block" else "high" if decision == "challenge" else "info",
            payload={"target_agent_id": str(target.id), "task": payload.task, "requested_permissions": payload.requested_permissions, "reasons": reasons},
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
def list_multi_agent_messages(db: Session = Depends(get_db)) -> list[MultiAgentMessage]:
    return db.query(MultiAgentMessage).order_by(desc(MultiAgentMessage.created_at)).limit(200).all()


@router.post("/sandbox/profiles", response_model=SandboxProfileRead, status_code=status.HTTP_201_CREATED)
def create_sandbox_profile(payload: SandboxProfileCreate, x_admin_api_key: str | None = Header(default=None), db: Session = Depends(get_db)) -> SandboxProfile:
    require_admin_key(x_admin_api_key)
    existing = db.query(SandboxProfile).filter(SandboxProfile.name == payload.name).one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="Sandbox profile already exists")
    profile = SandboxProfile(**payload.model_dump())
    db.add(profile)
    db.commit()
    db.refresh(profile)
    return profile


@router.get("/sandbox/profiles", response_model=list[SandboxProfileRead])
def list_sandbox_profiles(db: Session = Depends(get_db)) -> list[SandboxProfile]:
    return db.query(SandboxProfile).order_by(SandboxProfile.name).all()


@router.get("/baselines/agents/{agent_id}", response_model=BehaviorBaselineRead)
def get_behavior_baseline(agent_id: UUID, db: Session = Depends(get_db)) -> BehaviorBaseline:
    baseline = db.query(BehaviorBaseline).filter(BehaviorBaseline.agent_id == agent_id).one_or_none()
    if baseline is None:
        if db.get(Agent, agent_id) is None:
            raise HTTPException(status_code=404, detail="Agent not found")
        baseline = BehaviorBaseline(agent_id=agent_id)
        db.add(baseline)
        db.commit()
        db.refresh(baseline)
    return baseline


@router.post("/redteam/generate", response_model=list[RedTeamScenarioRead], status_code=status.HTTP_201_CREATED)
def generate_redteam(payload: RedTeamGenerateRequest, x_admin_api_key: str | None = Header(default=None), db: Session = Depends(get_db)) -> list[RedTeamScenario]:
    require_admin_key(x_admin_api_key)
    if payload.agent_id and db.get(Agent, payload.agent_id) is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    scenarios = generate_red_team_scenarios(agent_id=payload.agent_id, goal=payload.goal, tools=payload.tools, resources=payload.resources)
    db.add_all(scenarios)
    db.commit()
    for scenario in scenarios:
        db.refresh(scenario)
    return scenarios


@router.get("/redteam/scenarios", response_model=list[RedTeamScenarioRead])
def list_redteam_scenarios(db: Session = Depends(get_db)) -> list[RedTeamScenario]:
    return db.query(RedTeamScenario).order_by(desc(RedTeamScenario.created_at)).limit(200).all()


@router.post("/threats/indicators", response_model=ThreatIntelRead, status_code=status.HTTP_201_CREATED)
def create_threat_indicator(payload: ThreatIntelCreate, x_admin_api_key: str | None = Header(default=None), db: Session = Depends(get_db)) -> ThreatIntelIndicator:
    require_admin_key(x_admin_api_key)
    indicator = ThreatIntelIndicator(**payload.model_dump())
    db.add(indicator)
    db.commit()
    db.refresh(indicator)
    return indicator


@router.get("/threats/indicators", response_model=list[ThreatIntelRead])
def list_threat_indicators(active: bool | None = None, db: Session = Depends(get_db)) -> list[ThreatIntelIndicator]:
    query = db.query(ThreatIntelIndicator)
    if active is not None:
        query = query.filter(ThreatIntelIndicator.active == active)
    return query.order_by(desc(ThreatIntelIndicator.created_at)).limit(500).all()
