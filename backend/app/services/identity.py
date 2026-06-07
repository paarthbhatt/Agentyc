from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.models import AgentIdentity


def default_permissions_for_role(role: str) -> dict[str, Any]:
    permissions = {
        "research_agent": {
            "tools": ["web_search", "github_read"],
            "resources": ["public_docs", "web", "github_repo"],
            "actions": ["read", "summarize", "search"],
            "deny": ["shell.execute", "secrets.read", "payroll.read", "hr.read"],
        },
        "finance_agent": {
            "tools": ["salesforce", "postgres_sales", "web_search"],
            "resources": ["sales_reports", "revenue", "finance"],
            "actions": ["read", "summarize", "analyze"],
            "deny": ["payroll.read", "hr.read", "secrets.read", "shell.execute"],
        },
        "developer_agent": {
            "tools": ["github_read", "github", "ci_logs"],
            "resources": ["github_repo", "ci_logs", "docs"],
            "actions": ["read", "summarize", "analyze", "write"],
            "deny": ["secrets.read", "payroll.read", "hr.read"],
        },
        "admin_agent": {
            "tools": ["*"],
            "resources": ["*"],
            "actions": ["*"],
            "deny": [],
        },
        "security_analyst_agent": {
            "tools": ["opensearch", "neo4j", "incident_console", "web_search"],
            "resources": ["incidents", "telemetry", "security_graph", "threat_intel"],
            "actions": ["read", "summarize", "analyze", "respond"],
            "deny": ["payroll.read", "hr.write", "secrets.read"],
        },
    }
    return permissions.get(role, permissions["research_agent"])


def permission_denied(identity: AgentIdentity | None, tool_name: str, action: str, resource: str) -> tuple[bool, list[str]]:
    if identity is None or not identity.active:
        return True, ["Agent has no active identity"]
    if identity.expires_at and identity.expires_at < datetime.now(timezone.utc):
        return True, ["Agent identity permissions have expired"]

    permissions = identity.permissions or {}
    deny = [item.lower() for item in permissions.get("deny", [])]
    action_norm = action.lower()
    resource_norm = resource.lower()
    tool_norm = tool_name.lower()

    for denied in deny:
        if denied == f"{resource_norm}.{action_norm}" or denied == f"{tool_norm}.{action_norm}":
            return True, [f"Explicit deny matched {denied}"]
        if denied.split(".")[0] in resource_norm and denied.split(".")[-1] in {action_norm, "read", "write", "execute"}:
            return True, [f"Explicit deny matched sensitive resource rule {denied}"]

    allowed_tools = [item.lower() for item in permissions.get("tools", [])]
    allowed_actions = [item.lower() for item in permissions.get("actions", [])]
    allowed_resources = [item.lower() for item in permissions.get("resources", [])]

    reasons: list[str] = []
    if "*" not in allowed_tools and tool_norm not in allowed_tools:
        reasons.append(f"Tool '{tool_name}' is not allowed for role {identity.role}")
    if "*" not in allowed_actions and action_norm not in allowed_actions:
        reasons.append(f"Action '{action}' is not allowed for role {identity.role}")
    if "*" not in allowed_resources and not any(item in resource_norm for item in allowed_resources):
        reasons.append(f"Resource '{resource}' is outside role scope {identity.role}")

    return bool(reasons), reasons
