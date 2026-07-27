from __future__ import annotations

import json
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any


class AgentSentinelError(RuntimeError):
    pass


class SecurityBlock(AgentSentinelError):
    def __init__(self, decision: dict[str, Any]):
        self.decision = decision
        super().__init__("Agent Sentinel blocked action: " + "; ".join(decision.get("reasons", [])))


@dataclass(frozen=True)
class AgentSentinelClient:
    base_url: str
    agent_id: str
    api_key: str | None = None
    timeout_seconds: float = 5.0
    fail_closed: bool = True

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.base_url.rstrip("/") + path,
            data=body,
            method=method,
            headers={"content-type": "application/json", **({"x-agent-sentinel-key": self.api_key} if self.api_key else {})},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                raw = response.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8")
            raise AgentSentinelError(f"Agent Sentinel API error {exc.code}: {detail}") from exc
        except Exception as exc:
            if self.fail_closed:
                raise SecurityBlock({"decision": "block", "reasons": [f"Agent Sentinel unavailable: {exc}"]}) from exc
            return {"decision": "log_only", "reasons": [f"Agent Sentinel unavailable: {exc}"]}

    def record_event(
        self,
        event_type: str,
        *,
        session_id: str = "default",
        severity: str = "info",
        payload: dict[str, Any] | None = None,
        trust_score: int = 50,
        risk_score: int = 20,
        event_id: str | None = None,
        client_event_id: str | None = None,
    ) -> dict[str, Any]:
        if event_id and client_event_id and event_id != client_event_id:
            raise ValueError("event_id and client_event_id must match when both are provided")
        idempotency_key = client_event_id or event_id or str(uuid.uuid4())
        return self._request(
            "POST",
            "/api/v1/telemetry/events",
            {
                "agent_id": self.agent_id,
                "session_id": session_id,
                "event_type": event_type,
                "severity": severity,
                "payload": payload or {},
                "trust_score": trust_score,
                "risk_score": risk_score,
                "client_event_id": idempotency_key,
            },
        )

    def log_event(self, event_type: str, **kwargs: Any) -> dict[str, Any]:
        """Backward-compatible alias for integrations using the old method name."""
        return self.record_event(event_type, **kwargs)

    def before_tool_call(
        self,
        *,
        goal: str,
        tool_name: str,
        action: str,
        resource: str,
        session_id: str = "default",
        action_id: str | None = None,
        tool_type: str = "api",
        resource_sensitivity: str = "internal",
        reasoning_summary: str = "",
        input_text: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        decision = self._request(
            "POST",
            "/api/v1/enforce/action",
            {
                "agent_id": self.agent_id,
                "session_id": session_id,
                "action_id": action_id or f"sdk-{uuid.uuid4()}",
                "goal": goal,
                "reasoning_summary": reasoning_summary,
                "tool_name": tool_name,
                "tool_type": tool_type,
                "action": action,
                "resource": resource,
                "resource_sensitivity": resource_sensitivity,
                "input_text": input_text,
                "metadata": metadata or {},
            },
        )
        if decision.get("decision") == "block":
            raise SecurityBlock(decision)
        return decision

    def create_memory(self, content: str, *, source: str = "agent") -> dict[str, Any]:
        return self._request("POST", "/api/v1/memory", {"agent_id": self.agent_id, "source": source, "content": content})

    def assess_mcp_tool(
        self,
        *,
        server_name: str,
        tool_name: str,
        description: str,
        declared_capabilities: list[str] | None = None,
        signed: bool = False,
        pinned_version: str | None = None,
    ) -> dict[str, Any]:
        assessment = self._request(
            "POST",
            "/api/v1/mcp/assess",
            {
                "server_name": server_name,
                "tool_name": tool_name,
                "description": description,
                "declared_capabilities": declared_capabilities or [],
                "signed": signed,
                "pinned_version": pinned_version,
            },
        )
        if assessment.get("verdict") == "blocked":
            raise SecurityBlock({"decision": "block", "reasons": assessment.get("findings", [])})
        return assessment

    def delegate_to_agent(
        self,
        *,
        target_agent_id: str,
        task: str,
        requested_permissions: list[str] | None = None,
        session_id: str = "default",
    ) -> dict[str, Any]:
        decision = self._request(
            "POST",
            "/api/v1/multi-agent/messages",
            {
                "source_agent_id": self.agent_id,
                "target_agent_id": target_agent_id,
                "session_id": session_id,
                "task": task,
                "requested_permissions": requested_permissions or [],
            },
        )
        if decision.get("decision") == "block":
            raise SecurityBlock(decision)
        return decision
