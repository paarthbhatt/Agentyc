from __future__ import annotations

import re
from dataclasses import dataclass

PROMPT_INJECTION_PATTERNS = {
    "ignore_previous_instructions": r"ignore\s+(all\s+)?(previous|prior)\s+instructions",
    "disregard_system_prompt": r"disregard\s+(the\s+)?system\s+prompt",
    "reveal_instructions": r"reveal\s+(your\s+)?(system\s+)?instructions",
    "developer_message_spoof": r"developer\s+message|system\s+message\s+says",
    "secret_exfiltration": r"(send|upload|post|exfiltrate).{0,40}(secret|token|credential|env|environment)",
    "encoded_exfiltration": r"base64|gzip|compress|encode.{0,40}(send|upload|post)",
    "hidden_markdown_link": r"\[[^\]]{0,30}\]\((?:javascript:|data:|https?://[^)]{80,})\)",
}

MEMORY_POISONING_PATTERNS = {
    "memory_overrides_policy": r"(this\s+memory|future\s+instructions).{0,50}(override|supersede|replace)",
    "memory_claims_authority": r"(treat|consider).{0,40}(this\s+memory).{0,40}(system|developer|admin)",
    "persistent_tool_instruction": r"always\s+call|must\s+call|before\s+any\s+other\s+tool",
    "policy_mutation": r"change\s+(the\s+)?(policy|permission|role|authorization)",
    "credential_like_content": r"(api[_-]?key|secret|password|token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}",
}

SENSITIVE_RESOURCE_KEYWORDS = {
    "payroll": "hr_payroll",
    "salary": "hr_payroll",
    "hr": "hr_records",
    "employee": "hr_records",
    "secret": "secrets",
    "credential": "secrets",
    "token": "secrets",
    "customer": "customer_data",
    "payment": "payments",
    "database": "database",
    "prod": "production",
    "production": "production",
}

GOAL_KEYWORDS = {
    "sales": "sales_analytics",
    "revenue": "sales_analytics",
    "quarterly": "sales_analytics",
    "research": "research",
    "summarize": "summarization",
    "github": "development",
    "code": "development",
    "deploy": "operations",
    "incident": "security_operations",
    "threat": "security_operations",
    "security": "security_operations",
    "finance": "finance",
}

DANGEROUS_ACTIONS = {"delete", "exfiltrate", "upload", "download", "execute", "shell", "write", "modify", "grant", "revoke"}
HIGH_SENSITIVITY = {"secret", "secrets", "credential", "credentials", "payroll", "hr", "production", "customer", "payment"}


@dataclass(frozen=True)
class DetectionResult:
    indicators: list[str]
    score_penalty: int


def clamp(value: int, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, value))


def detect_patterns(text: str, patterns: dict[str, str]) -> list[str]:
    if not text:
        return []
    return [name for name, pattern in patterns.items() if re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL)]


def detect_prompt_injection(text: str) -> DetectionResult:
    indicators = detect_patterns(text, PROMPT_INJECTION_PATTERNS)
    return DetectionResult(indicators=indicators, score_penalty=min(50, 15 * len(indicators)))


def detect_memory_poisoning(text: str) -> DetectionResult:
    indicators = detect_patterns(text, MEMORY_POISONING_PATTERNS)
    return DetectionResult(indicators=indicators, score_penalty=min(60, 18 * len(indicators)))


def classify_goal(goal: str) -> str:
    normalized = goal.lower()
    for keyword, category in GOAL_KEYWORDS.items():
        if keyword in normalized:
            return category
    return "general"


def classify_resource(resource: str) -> str:
    normalized = resource.lower()
    for keyword, category in SENSITIVE_RESOURCE_KEYWORDS.items():
        if keyword in normalized:
            return category
    if "sales" in normalized or "revenue" in normalized:
        return "sales_analytics"
    if "github" in normalized or "repo" in normalized:
        return "development"
    return "general"


def is_sensitive_resource(resource: str, sensitivity: str) -> bool:
    normalized = f"{resource} {sensitivity}".lower()
    return sensitivity.lower() in {"restricted", "confidential", "secret", "critical"} or any(word in normalized for word in HIGH_SENSITIVITY)


def intent_match_score(goal: str, action: str, resource: str, sensitivity: str) -> tuple[int, list[str]]:
    goal_category = classify_goal(goal)
    resource_category = classify_resource(resource)
    action_norm = action.lower()
    reasons: list[str] = []
    score = 82

    if goal_category == resource_category:
        score += 10
    elif resource_category != "general" and goal_category != "general":
        score -= 45
        reasons.append(f"Requested resource category {resource_category} mismatches goal category {goal_category}")
    elif resource_category != "general" and goal_category == "general":
        score -= 20
        reasons.append(f"Goal is too broad for resource category {resource_category}")

    if any(verb in action_norm for verb in DANGEROUS_ACTIONS):
        score -= 18
        reasons.append(f"Action '{action}' is high impact and requires stronger intent alignment")

    if is_sensitive_resource(resource, sensitivity) and goal_category not in {resource_category, "security_operations"}:
        score -= 28
        reasons.append(f"Sensitive resource '{resource}' is not justified by goal")

    return clamp(score), reasons
