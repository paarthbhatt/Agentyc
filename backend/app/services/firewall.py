from __future__ import annotations

import json
import uuid

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.metrics import record_decision
from app.core.security import sha256_text
from app.models import Agent, AttestationRecord, MemoryObject, PolicyPack, TelemetryEvent, Tool
from app.schemas import EnforcementDecision, EnforcementRequest
from app.services.detection import (
    detect_prompt_injection,
    intent_match_score,
    is_sensitive_resource,
)
from app.services.identity import permission_denied
from app.services.incident_response import create_incident, recommended_actions
from app.services.outbox import queue_integration
from app.services.risk_engine import calculate_action_risk, decision_for_scores, severity_from_score
from app.services.trust_engine import effective_tool_trust, memory_influence_trust, propagate_trust


def _incident_category(
    reasons: list[str], prompt_indicators: list[str], request: EnforcementRequest
) -> str:
    joined = " ".join(reasons).lower()
    if prompt_indicators:
        return "prompt_injection"
    if "identity" in joined or "permission" in joined or "explicit deny" in joined:
        return "identity_violation"
    if "mcp" in request.tool_type.lower() or "mcp" in request.tool_name.lower():
        return "mcp_tool_poisoning"
    if (
        "exfiltrat" in joined
        or "secret" in request.resource.lower()
        or "credential" in request.resource.lower()
    ):
        return "data_exfiltration"
    if "intent" in joined or "mismatch" in joined:
        return "intent_mismatch"
    return "tool_abuse"


def evaluate_and_record(
    db: Session, request: EnforcementRequest, *, org_id=None
) -> EnforcementDecision:
    agent_query = db.query(Agent).filter(Agent.id == request.agent_id)
    if org_id is not None:
        agent_query = agent_query.filter(Agent.org_id == org_id)
    agent = agent_query.one_or_none()
    if agent is None:
        raise ValueError("agent_not_found")

    if request.action_id:
        existing = (
            db.query(AttestationRecord)
            .filter(
                AttestationRecord.org_id == agent.org_id,
                AttestationRecord.agent_id == agent.id,
                AttestationRecord.action_id == request.action_id,
            )
            .one_or_none()
        )
        if existing and existing.decision_payload:
            return EnforcementDecision.model_validate(existing.decision_payload)

    policy = (
        db.query(PolicyPack)
        .filter(PolicyPack.org_id == agent.org_id, PolicyPack.is_active.is_(True))
        .order_by(PolicyPack.created_at.desc())
        .first()
    )
    intent_threshold = policy.intent_match_threshold if policy else 70
    tool_threshold = policy.tool_trust_threshold if policy else 60
    memory_threshold = policy.memory_trust_threshold if policy else 55

    tool = (
        db.query(Tool)
        .filter(Tool.org_id == agent.org_id, Tool.name == request.tool_name)
        .one_or_none()
    )
    tool_trust, tool_reasons = effective_tool_trust(
        tool, request.tool_name, request.tool_type, request.metadata.get("tool_description", "")
    )
    memories = []
    if request.memory_object_ids:
        memories = (
            db.query(MemoryObject)
            .filter(
                MemoryObject.org_id == agent.org_id,
                MemoryObject.id.in_(request.memory_object_ids),
            )
            .all()
        )
    memory_trust, memory_reasons = memory_influence_trust(memories)

    prompt_detection = detect_prompt_injection(
        "\n".join(
            [
                request.input_text,
                request.reasoning_summary,
                request.metadata.get("tool_description", ""),
            ]
        )
    )
    intent_score, intent_reasons = intent_match_score(
        request.goal, request.action, request.resource, request.resource_sensitivity
    )
    denied, permission_reasons = permission_denied(
        agent.identity, request.tool_name, request.action, request.resource
    )
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
    trust_score = propagate_trust(
        [tool_trust, memory_trust, agent.trust_level], penalties=prompt_detection.score_penalty
    )
    sensitive = is_sensitive_resource(request.resource, request.resource_sensitivity)
    decision = decision_for_scores(
        risk_score, intent_score, tool_trust, denied, sensitive, intent_threshold, tool_threshold
    )
    severity = severity_from_score(risk_score)

    reasons = []
    reasons.extend(intent_reasons)
    reasons.extend(permission_reasons)
    reasons.extend(tool_reasons)
    reasons.extend(memory_reasons)
    reasons.extend(risk_reasons)
    reasons.extend(
        [f"Prompt indicator detected: {indicator}" for indicator in prompt_detection.indicators]
    )
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
    if db.bind and db.bind.dialect.name == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:lock_key))"),
            {"lock_key": f"attestation:{agent.id}"},
        )
    previous_attestation = (
        db.query(AttestationRecord)
        .filter(AttestationRecord.org_id == agent.org_id, AttestationRecord.agent_id == agent.id)
        .order_by(AttestationRecord.created_at.desc(), AttestationRecord.id.desc())
        .with_for_update()
        .first()
    )
    attestation = AttestationRecord(
        org_id=agent.org_id,
        agent_id=agent.id,
        action_id=action_id,
        session_id=request.session_id,
        goal=request.goal,
        reasoning_summary=request.reasoning_summary[:4000],
        resources_accessed=[request.resource],
        security_score=100 - risk_score,
        policy_id=policy.id if policy else None,
        policy_version=policy.version if policy else None,
        previous_hash=previous_attestation.record_hash if previous_attestation else None,
        record_hash=sha256_text(json.dumps(attestation_payload, sort_keys=True)),
    )
    db.add(attestation)

    event_type = (
        "tool.blocked"
        if decision == "block"
        else "tool.allowed"
        if decision == "allow"
        else "policy.violation"
    )
    event = TelemetryEvent(
        org_id=agent.org_id,
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
            "policy_id": str(policy.id) if policy else None,
            "policy_version": policy.version if policy else None,
            "reasons": reasons,
        },
        trust_score=trust_score,
        risk_score=risk_score,
    )
    db.add(event)

    incident_id = None
    actions = recommended_actions(
        _incident_category(reasons, prompt_detection.indicators, request), severity
    )
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
                "policy_id": str(policy.id) if policy else None,
                "policy_version": policy.version if policy else None,
                "reasons": reasons,
            },
            response_actions=actions,
        )
        incident_id = incident.id

    if tool:
        tool.usage_count += 1
    agent.risk_score = max(
        agent.risk_score,
        risk_score if decision != "allow" else int((agent.risk_score + risk_score) / 2),
    )
    agent.trust_level = min(agent.trust_level, trust_score)

    db.flush()
    result = EnforcementDecision(
        decision=decision,
        intent_match_score=intent_score,
        risk_score=risk_score,
        trust_score=trust_score,
        severity=severity,
        reasons=reasons,
        recommended_response_actions=actions if decision != "allow" else [],
        incident_id=incident_id,
        attestation_id=attestation.id,
        policy_id=policy.id if policy else None,
        policy_version=policy.version if policy else None,
    )
    attestation.decision_payload = result.model_dump(mode="json")
    attestation_payload["previous_hash"] = attestation.previous_hash
    attestation_payload["policy_id"] = str(policy.id) if policy else None
    attestation_payload["policy_version"] = policy.version if policy else None
    attestation.record_hash = sha256_text(json.dumps(attestation_payload, sort_keys=True))
    queue_integration(
        db,
        org_id=agent.org_id,
        event_type="telemetry.created",
        aggregate_type="telemetry",
        aggregate_id=str(event.id),
    )
    queue_integration(
        db,
        org_id=agent.org_id,
        event_type="baseline.recalculate",
        aggregate_type="agent",
        aggregate_id=str(agent.id),
    )
    db.flush()
    record_decision(decision)
    return result
