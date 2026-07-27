from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.api.auth import Principal, get_current_principal
from app.db.session import get_db
from app.models import Agent, Tool
from app.services.detection import MEMORY_POISONING_PATTERNS, PROMPT_INJECTION_PATTERNS

router = APIRouter()


@router.get("/threats")
def list_threats(principal: Principal = Depends(get_current_principal)) -> dict:
    return {
        "prompt_injection_patterns": sorted(PROMPT_INJECTION_PATTERNS.keys()),
        "memory_poisoning_patterns": sorted(MEMORY_POISONING_PATTERNS.keys()),
        "mcp_security": [
            "malicious_tool_description",
            "hidden_instructions",
            "broad_filesystem_access",
            "unsigned_server",
        ],
    }


@router.get("/risk/agents")
def agent_risk(
    principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)
) -> list[dict]:
    agents = (
        db.query(Agent)
        .filter(Agent.org_id == principal.org_id)
        .order_by(desc(Agent.risk_score))
        .limit(50)
        .all()
    )
    return [
        {
            "id": str(agent.id),
            "name": agent.name,
            "risk_score": agent.risk_score,
            "trust_level": agent.trust_level,
            "status": agent.status,
        }
        for agent in agents
    ]


@router.get("/trust/tools")
def tool_trust(
    principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)
) -> list[dict]:
    tools = db.query(Tool).filter(Tool.org_id == principal.org_id).order_by(Tool.trust_score).all()
    return [
        {
            "id": str(tool.id),
            "name": tool.name,
            "type": tool.type,
            "trust_score": tool.trust_score,
            "status": tool.status,
            "incident_count": tool.incident_count,
        }
        for tool in tools
    ]
