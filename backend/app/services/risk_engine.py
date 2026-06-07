from __future__ import annotations

from app.services.detection import clamp, is_sensitive_resource


def severity_from_score(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def calculate_action_risk(
    *,
    intent_match_score: int,
    tool_trust_score: int,
    memory_trust_score: int,
    permission_denied: bool,
    prompt_penalty: int,
    resource: str,
    resource_sensitivity: str,
    historical_incidents: int,
) -> tuple[int, list[str]]:
    risk = 15
    reasons: list[str] = []

    if intent_match_score < 70:
        delta = 70 - intent_match_score
        risk += delta
        reasons.append(f"Intent match below safe threshold by {delta} points")

    if tool_trust_score < 60:
        delta = 60 - tool_trust_score
        risk += delta
        reasons.append(f"Tool trust below safe threshold by {delta} points")

    if memory_trust_score < 55:
        delta = 55 - memory_trust_score
        risk += delta
        reasons.append(f"Memory influence trust below safe threshold by {delta} points")

    if permission_denied:
        risk += 45
        reasons.append("Agent identity does not permit this action")

    if prompt_penalty:
        risk += prompt_penalty
        reasons.append("Prompt or tool input contains injection/exfiltration indicators")

    if is_sensitive_resource(resource, resource_sensitivity):
        risk += 15
        reasons.append("Requested resource is sensitive")

    if historical_incidents:
        risk += min(20, historical_incidents * 5)
        reasons.append(f"Agent has {historical_incidents} historical incident(s)")

    return clamp(risk), reasons


def decision_for_scores(risk_score: int, intent_score: int, tool_trust_score: int, permission_denied: bool, sensitive: bool) -> str:
    if permission_denied:
        return "block"
    if intent_score < 35:
        return "block"
    if risk_score >= 85:
        return "block"
    if tool_trust_score < 30 and sensitive:
        return "block"
    if risk_score >= 70:
        return "challenge"
    return "allow"
