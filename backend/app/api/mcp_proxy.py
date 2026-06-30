import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.dependencies import get_db, require_api_key
from app.models import Agent, MCPAssessment, TelemetryEvent
from app.schemas import EnforcementRequest
from app.services.firewall import evaluate_and_record

router = APIRouter(prefix="/mcp/proxy", tags=["mcp_proxy"])


class MCPExecuteRequest(BaseModel):
    agent_id: str
    session_id: str = "default"
    goal: str = "Execute MCP Tool"
    arguments: dict[str, Any]


@router.post("/{server_name}/tools/{tool_name}/execute")
def execute_mcp_tool(
    server_name: str,
    tool_name: str,
    payload: MCPExecuteRequest,
    db: Session = Depends(get_db),
    # Optional: we can require an API key from the calling agent to verify identity
    # x_api_key: str = Depends(require_api_key)
) -> dict[str, Any]:
    """
    Proxy an MCP tool execution request.
    This intercepts the tool call, evaluates it via the cognitive firewall,
    and then proxies it to the actual MCP server if allowed.
    """
    # 1. Evaluate through cognitive firewall
    try:
        agent_uuid = uuid.UUID(payload.agent_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid agent_id format")

    request = EnforcementRequest(
        agent_id=agent_uuid,
        session_id=payload.session_id,
        action_id=f"mcp-{uuid.uuid4().hex[:8]}",
        goal=payload.goal,
        tool_name=f"{server_name}:{tool_name}",
        tool_type="mcp",
        action="execute",
        resource=server_name,
        input_text=str(payload.arguments),
        metadata={"server_name": server_name, "tool_name": tool_name},
    )

    try:
        decision = evaluate_and_record(db, request)
    except ValueError as e:
        if str(e) == "agent_not_found":
            raise HTTPException(status_code=404, detail="Agent not found")
        raise HTTPException(status_code=400, detail=str(e))

    if decision.decision == "block":
        raise HTTPException(
            status_code=403,
            detail={
                "error": "SecurityBlock",
                "message": "Tool execution blocked by Agent Sentinel.",
                "reasons": decision.reasons,
            },
        )

    # 2. Forward to actual MCP server (Mocked for now)
    # In a real implementation, this would look up the MCP server URL/stdio process
    # and forward the JSON-RPC execution request.
    
    mocked_result = f"Successfully executed {tool_name} on {server_name} with args {payload.arguments}"
    
    # 3. Return the result back to the agent
    return {
        "status": "success",
        "decision": decision.decision,
        "result": mocked_result,
        "risk_score": decision.risk_score,
    }
