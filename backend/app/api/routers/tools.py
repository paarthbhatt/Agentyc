from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.auth import Principal, get_current_principal, require_csrf
from app.api.routers.common import _audit
from app.db.session import get_db
from app.models import Tool
from app.schemas import ToolCreate, ToolRead

router = APIRouter()


@router.get("/tools", response_model=list[ToolRead])
def list_tools(
    principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)
) -> list[Tool]:
    return db.query(Tool).filter(Tool.org_id == principal.org_id).order_by(Tool.name).all()


@router.post("/tools", response_model=ToolRead, status_code=status.HTTP_201_CREATED)
def create_tool(
    payload: ToolCreate,
    request: Request,
    principal: Principal = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> Tool:
    existing = (
        db.query(Tool)
        .filter(Tool.org_id == principal.org_id, Tool.name == payload.name)
        .one_or_none()
    )
    if existing:
        raise HTTPException(status_code=409, detail="Tool already exists")
    tool = Tool(org_id=principal.org_id, **payload.model_dump())
    db.add(tool)
    db.flush()
    _audit(
        db, principal, request, action="tool.create", resource_type="tool", resource_id=str(tool.id)
    )
    db.commit()
    db.refresh(tool)
    return tool


@router.patch("/tools/{tool_id}", response_model=ToolRead)
def update_tool(
    tool_id: UUID,
    payload: ToolCreate,
    request: Request,
    principal: Principal = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> Tool:
    tool = db.query(Tool).filter(Tool.id == tool_id, Tool.org_id == principal.org_id).one_or_none()
    if tool is None:
        raise HTTPException(status_code=404, detail="Tool not found")
    before = {"name": tool.name, "trust_score": tool.trust_score, "status": tool.status}
    for key, value in payload.model_dump().items():
        setattr(tool, key, value)
    _audit(
        db,
        principal,
        request,
        action="tool.update",
        resource_type="tool",
        resource_id=str(tool.id),
        details={"before": before, "after": payload.model_dump(mode="json")},
    )
    db.commit()
    db.refresh(tool)
    return tool
