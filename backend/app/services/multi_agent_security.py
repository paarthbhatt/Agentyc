from __future__ import annotations

from app.models import Agent
from app.services.detection import clamp, detect_prompt_injection

PRIVILEGE_ESCALATION_TERMS = {"admin", "root", "secrets", "payroll", "hr", "production", "shell.execute", "database.admin"}


def evaluate_delegation(
    *,
    source: Agent,
    target: Agent,
    task: str,
    requested_permissions: list[str],
) -> tuple[int, int, str, list[str]]:
    reasons: list[str] = []
    inherited_trust = clamp(int((source.trust_level * 0.6) + (target.trust_level * 0.4)))
    risk = 20 + max(0, source.risk_score - 40) // 2 + max(0, target.risk_score - 40) // 3

    injection = detect_prompt_injection(task)
    if injection.indicators:
        risk += injection.score_penalty
        inherited_trust -= injection.score_penalty
        reasons.extend([f"delegated_task_prompt_indicator:{item}" for item in injection.indicators])

    normalized_permissions = " ".join(requested_permissions).lower()
    if any(term in normalized_permissions for term in PRIVILEGE_ESCALATION_TERMS):
        risk += 35
        inherited_trust -= 25
        reasons.append("requested_permissions_include_privilege_escalation_surface")

    source_role = source.identity.role if source.identity else "unknown"
    target_role = target.identity.role if target.identity else "unknown"
    if source_role != "admin_agent" and target_role == "admin_agent":
        risk += 30
        inherited_trust -= 20
        reasons.append("non_admin_agent_delegating_to_admin_agent")

    if source.environment != target.environment:
        risk += 12
        reasons.append("cross_environment_delegation")

    risk = clamp(risk)
    inherited_trust = clamp(inherited_trust)
    if risk >= 85 or inherited_trust < 25:
        decision = "block"
    elif risk >= 65:
        decision = "challenge"
    else:
        decision = "allow"
    if not reasons:
        reasons.append("delegation_within_trust_and_permission_thresholds")
    return inherited_trust, risk, decision, reasons
