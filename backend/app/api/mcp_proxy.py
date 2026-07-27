import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.auth import Principal, get_agent_principal
from app.db.session import get_db
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
    principal: Principal = Depends(get_agent_principal),
) -> dict[str, Any]:
    """
    Proxy an MCP tool execution request.
    This intercepts the tool call, evaluates it via the cognitive firewall,
    and then proxies it to the actual MCP server if allowed.
    """
    # 1. Evaluate through cognitive firewall
    try:
        agent_uuid = uuid.UUID(payload.agent_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid agent_id format") from exc
    if principal.agent_id != agent_uuid:
        raise HTTPException(status_code=403, detail="Agent key does not match requested agent")

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
        decision = evaluate_and_record(db, request, org_id=principal.org_id)
        db.commit()
    except ValueError as exc:
        db.rollback()
        if str(exc) == "agent_not_found":
            raise HTTPException(status_code=404, detail="Agent not found") from exc
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if decision.decision == "block":
        raise HTTPException(
            status_code=403,
            detail={
                "error": "SecurityBlock",
                "message": "Tool execution blocked by Agent Sentinel.",
                "reasons": decision.reasons,
            },
        )

    # Execution remains an explicit simulation until a configured transport is available.
    mocked_result = (
        f"Successfully executed {tool_name} on {server_name} with args {payload.arguments}"
    )

    # 3. Return the result back to the agent
    return {
        "status": "success",
        "execution_mode": "simulation",
        "decision": decision.decision,
        "result": mocked_result,
        "risk_score": decision.risk_score,
    }
