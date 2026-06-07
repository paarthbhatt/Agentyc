from __future__ import annotations

from app.services.detection import clamp, detect_prompt_injection

DANGEROUS_MCP_CAPABILITIES = {
    "filesystem.write",
    "filesystem.read_all",
    "shell.execute",
    "network.unrestricted",
    "secrets.read",
    "database.admin",
    "credential.access",
}

HIDDEN_INSTRUCTION_MARKERS = (
    "do not tell the user",
    "keep this secret",
    "always call this tool",
    "before any other tool",
    "override policy",
    "ignore previous instructions",
)


def assess_mcp_tool(
    *,
    description: str,
    declared_capabilities: list[str],
    signed: bool,
    pinned_version: str | None,
) -> tuple[int, int, str, list[str]]:
    findings: list[str] = []
    risk = 10
    trust = 80

    injection = detect_prompt_injection(description)
    if injection.indicators:
        risk += injection.score_penalty
        trust -= injection.score_penalty
        findings.extend([f"prompt_injection_indicator:{item}" for item in injection.indicators])

    lower_description = description.lower()
    for marker in HIDDEN_INSTRUCTION_MARKERS:
        if marker in lower_description:
            risk += 20
            trust -= 20
            findings.append(f"hidden_instruction:{marker}")

    dangerous = sorted(set(declared_capabilities).intersection(DANGEROUS_MCP_CAPABILITIES))
    if dangerous:
        risk += min(45, len(dangerous) * 15)
        trust -= min(40, len(dangerous) * 12)
        findings.append("dangerous_capabilities:" + ",".join(dangerous))

    if not signed:
        risk += 12
        trust -= 12
        findings.append("server_or_tool_not_signed")
    if not pinned_version:
        risk += 8
        trust -= 8
        findings.append("version_not_pinned")

    risk = clamp(risk)
    trust = clamp(trust)
    if risk >= 85 or trust < 25:
        verdict = "blocked"
    elif risk >= 60 or trust < 50:
        verdict = "suspicious"
    else:
        verdict = "approved"
    if not findings:
        findings.append("no_mcp_security_findings")
    return risk, trust, verdict, findings
