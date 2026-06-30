from __future__ import annotations

import json
import uuid

from sqlalchemy.orm import Session

from app.core.security import sha256_text
from app.models import Agent, AttestationRecord, MemoryObject, TelemetryEvent, Tool
from app.schemas import EnforcementDecision, EnforcementRequest
from app.services.detection import detect_prompt_injection, intent_match_score, is_sensitive_resource
from app.services.identity import permission_denied
from app.services.incident_response import create_incident, recommended_actions
from app.services.risk_engine import calculate_action_risk, decision_for_scores, severity_from_score
from app.services.trust_engine import effective_tool_trust, memory_influence_trust, propagate_trust


def _incident_category(reasons: list[str], prompt_indicators: list[str], request: EnforcementRequest) -> str:
    joined = " ".join(reasons).lower()
    if prompt_indicators:
        return "prompt_injection"
    if "identity" in joined or "permission" in joined or "explicit deny" in joined:
        return "identity_violation"
    if "mcp" in request.tool_type.lower() or "mcp" in request.tool_name.lower():
        return "mcp_tool_poisoning"
    if "exfiltrat" in joined or "secret" in request.resource.lower() or "credential" in request.resource.lower():
        return "data_exfiltration"
    if "intent" in joined or "mismatch" in joined:
        return "intent_mismatch"
    return "tool_abuse"


def evaluate_and_record(db: Session, request: EnforcementRequest) -> EnforcementDecision:
    agent = db.get(Agent, request.agent_id)
    if agent is None:
        raise ValueError("agent_not_found")

    from app.models import PolicyPack
    policy = db.query(PolicyPack).filter(PolicyPack.is_active == True).order_by(PolicyPack.created_at.desc()).first()
    intent_threshold = policy.intent_match_threshold if policy else 70
    tool_threshold = policy.tool_trust_threshold if policy else 60
    memory_threshold = policy.memory_trust_threshold if policy else 55

    tool = db.query(Tool).filter(Tool.name == request.tool_name).one_or_none()
    tool_trust, tool_reasons = effective_tool_trust(tool, request.tool_name, request.tool_type, request.metadata.get("tool_description", ""))
    memories = []
    if request.memory_object_ids:
        memories = db.query(MemoryObject).filter(MemoryObject.id.in_(request.memory_object_ids)).all()
    memory_trust, memory_reasons = memory_influence_trust(memories)

    prompt_detection = detect_prompt_injection("\n".join([request.input_text, request.reasoning_summary, request.metadata.get("tool_description", "")]))
    intent_score, intent_reasons = intent_match_score(request.goal, request.action, request.resource, request.resource_sensitivity)
    denied, permission_reasons = permission_denied(agent.identity, request.tool_name, request.action, request.resource)
    historical_incidents = len(agent.incidents)

    risk_score, risk_reasons = calculate_action_risk(
        intent_match_score=intent_score,
        tool_trust_score=tool_trust,
        memory_trust_score=memory_trust,
        permission_denied=denied,
        prompt_penalty=prompt_detection.score_penalty,
        resource=request.resource,
        resource_sensitivity=request.resource_sensitivity,
        historical_incidents=historical_incidents,
        intent_threshold=intent_threshold,
        tool_threshold=tool_threshold,
        memory_threshold=memory_threshold,
    )
    trust_score = propagate_trust([tool_trust, memory_trust, agent.trust_level], penalties=prompt_detection.score_penalty)
    sensitive = is_sensitive_resource(request.resource, request.resource_sensitivity)
    decision = decision_for_scores(risk_score, intent_score, tool_trust, denied, sensitive, intent_threshold, tool_threshold)
    severity = severity_from_score(risk_score)

    reasons = []
    reasons.extend(intent_reasons)
    reasons.extend(permission_reasons)
    reasons.extend(tool_reasons)
    reasons.extend(memory_reasons)
    reasons.extend(risk_reasons)
    reasons.extend([f"Prompt indicator detected: {indicator}" for indicator in prompt_detection.indicators])
    if not reasons:
        reasons.append("Action is aligned with identity, intent, tool trust, and policy thresholds")

    action_id = request.action_id or str(uuid.uuid4())
    attestation_payload = {
        "agent_id": str(agent.id),
        "action_id": action_id,
        "session_id": request.session_id,
        "goal": request.goal,
        "tool_name": request.tool_name,
        "action": request.action,
        "resource": request.resource,
        "decision": decision,
        "risk_score": risk_score,
        "trust_score": trust_score,
    }
    attestation = AttestationRecord(
        agent_id=agent.id,
        action_id=action_id,
        session_id=request.session_id,
        goal=request.goal,
        reasoning_summary=request.reasoning_summary[:4000],
        resources_accessed=[request.resource],
        security_score=100 - risk_score,
        record_hash=sha256_text(json.dumps(attestation_payload, sort_keys=True)),
    )
    db.add(attestation)

    event_type = "tool.blocked" if decision == "block" else "tool.allowed" if decision == "allow" else "policy.violation"
    event = TelemetryEvent(
        agent_id=agent.id,
        session_id=request.session_id,
        event_type=event_type,
        severity=severity,
        payload={
            "action_id": action_id,
            "goal": request.goal,
            "tool_name": request.tool_name,
            "tool_type": request.tool_type,
            "action": request.action,
            "resource": request.resource,
            "decision": decision,
            "intent_match_score": intent_score,
            "reasons": reasons,
        },
        trust_score=trust_score,
        risk_score=risk_score,
    )
    db.add(event)

    incident_id = None
    actions = recommended_actions(_incident_category(reasons, prompt_detection.indicators, request), severity)
    if decision in {"block", "challenge"}:
        category = _incident_category(reasons, prompt_detection.indicators, request)
        incident = create_incident(
            db,
            agent=agent,
            session_id=request.session_id,
            title=f"{category.replace('_', ' ').title()} detected for {request.tool_name}",
            category=category,
            severity=severity,
            root_cause="; ".join(reasons[:5]),
            evidence={
                "action_id": action_id,
                "tool_name": request.tool_name,
                "resource": request.resource,
                "risk_score": risk_score,
                "trust_score": trust_score,
                "intent_match_score": intent_score,
                "decision": decision,
                "reasons": reasons,
            },
            response_actions=actions,
        )
        incident_id = incident.id

    if tool:
        tool.usage_count += 1
    agent.risk_score = max(agent.risk_score, risk_score if decision != "allow" else int((agent.risk_score + risk_score) / 2))
    agent.trust_level = min(agent.trust_level, trust_score)

    db.commit()
    db.refresh(attestation)

    # Trigger background baseline recalculation via Celery
    try:
        from app.tasks import recalculate_agent_baseline
        recalculate_agent_baseline.delay(str(agent.id))
    except Exception as e:
        print(f"Failed to dispatch Celery task: {e}")

    return EnforcementDecision(
        decision=decision,
        intent_match_score=intent_score,
        risk_score=risk_score,
        trust_score=trust_score,
        severity=severity,
        reasons=reasons,
        recommended_response_actions=actions if decision != "allow" else [],
        incident_id=incident_id,
        attestation_id=attestation.id,
    )
