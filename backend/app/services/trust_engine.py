from __future__ import annotations

from app.models import MemoryObject, Tool
from app.services.detection import clamp, detect_prompt_injection

TOOL_TYPE_RISK = {
    "shell": 35,
    "filesystem": 25,
    "database": 20,
    "mcp": 25,
    "api": 10,
    "website": 15,
    "plugin": 18,
}


def default_tool_trust(name: str, tool_type: str, description: str = "") -> tuple[int, list[str]]:
    lower_name = name.lower()
    reasons: list[str] = []
    score = 55

    if lower_name in {"github", "github_read", "slack", "salesforce", "stripe"}:
        score += 25
        reasons.append("Known vendor or first-party integration")
    if "unknown" in lower_name or tool_type == "mcp":
        score -= 18
        reasons.append("Unknown or MCP tool requires elevated scrutiny")

    injection = detect_prompt_injection(description)
    if injection.indicators:
        score -= injection.score_penalty
        reasons.append("Tool description contains instruction-injection indicators")

    score -= TOOL_TYPE_RISK.get(tool_type, 12)
    return clamp(score), reasons


def effective_tool_trust(
    tool: Tool | None, tool_name: str, tool_type: str, description: str = ""
) -> tuple[int, list[str]]:
    if tool is None:
        score, reasons = default_tool_trust(tool_name, tool_type, description)
        reasons.append("Tool is not registered in trust registry")
        return score, reasons

    reasons = [f"Registered tool trust score is {tool.trust_score}"]
    if tool.status not in {"verified", "approved"}:
        reasons.append(f"Tool status is {tool.status}")
    if tool.incident_count > 0:
        reasons.append(f"Tool has {tool.incident_count} prior incident(s)")
    adjusted = tool.trust_score - min(25, tool.incident_count * 10)
    if tool.status in {"verified", "approved"}:
        adjusted += 5
    return clamp(adjusted), reasons


def propagate_trust(parent_scores: list[int], penalties: int = 0, bonus: int = 0) -> int:
    if not parent_scores:
        base = 50
    else:
        base = int(sum(parent_scores) / len(parent_scores))
    return clamp(base - penalties + bonus)


def memory_influence_trust(memory_objects: list[MemoryObject]) -> tuple[int, list[str]]:
    if not memory_objects:
        return 70, []
    scores = [memory.trust_level for memory in memory_objects]
    reasons = [
        f"Memory object {memory.id} trust={memory.trust_level} status={memory.security_status}"
        for memory in memory_objects
    ]
    return propagate_trust(scores), reasons
