from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.api.auth import Principal, get_current_principal, get_tenant_principal
from app.core.security import sha256_text
from app.db.session import get_db
from app.models import MCPAssessment, Tool
from app.schemas import MCPAssessmentCreate, MCPAssessmentRead
from app.services.mcp_security import assess_mcp_tool

router = APIRouter()


@router.post("/mcp/assess", response_model=MCPAssessmentRead, status_code=status.HTTP_201_CREATED)
def assess_mcp(
    payload: MCPAssessmentCreate,
    principal: Principal = Depends(get_tenant_principal),
    db: Session = Depends(get_db),
) -> MCPAssessment:
    if principal.actor_type == "user" and "write" not in principal.scopes:
        raise HTTPException(status_code=403, detail="Write scope required")
    risk_score, trust_score, verdict, findings = assess_mcp_tool(
        description=payload.description,
        declared_capabilities=payload.declared_capabilities,
        signed=payload.signed,
        pinned_version=payload.pinned_version,
    )
    assessment = MCPAssessment(
        org_id=principal.org_id,
        server_name=payload.server_name,
        tool_name=payload.tool_name,
        description_hash=sha256_text(payload.description),
        risk_score=risk_score,
        trust_score=trust_score,
        verdict=verdict,
        findings=findings,
    )
    db.add(assessment)
    tool = (
        db.query(Tool)
        .filter(Tool.org_id == principal.org_id, Tool.name == payload.tool_name)
        .one_or_none()
    )
    if tool:
        tool.trust_score = min(tool.trust_score, trust_score)
        if verdict in {"blocked", "suspicious"}:
            tool.status = verdict
            tool.known_risks = list(dict.fromkeys([*(tool.known_risks or []), *findings]))
    db.commit()
    db.refresh(assessment)
    return assessment


@router.get("/mcp/assessments", response_model=list[MCPAssessmentRead])
def list_mcp_assessments(
    principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)
) -> list[MCPAssessment]:
    return (
        db.query(MCPAssessment)
        .filter(MCPAssessment.org_id == principal.org_id)
        .order_by(desc(MCPAssessment.created_at))
        .limit(200)
        .all()
    )
