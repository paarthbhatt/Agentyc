from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.api.auth import Principal, get_agent_principal, get_current_principal
from app.api.routers.common import _agent_for_org, _assert_agent, _audit
from app.db.session import get_db
from app.models import MemoryObject
from app.schemas import MemoryCreate, MemoryRead
from app.services.memory_security import create_memory_object

router = APIRouter()


@router.post("/memory", response_model=MemoryRead, status_code=status.HTTP_201_CREATED)
def create_memory(
    payload: MemoryCreate,
    request: Request,
    principal: Principal = Depends(get_agent_principal),
    db: Session = Depends(get_db),
) -> MemoryObject:
    _assert_agent(principal, payload.agent_id)
    agent = _agent_for_org(db, payload.agent_id, principal.org_id)
    memory = create_memory_object(db, agent=agent, source=payload.source, content=payload.content)
    _audit(
        db,
        principal,
        request,
        action="memory.create",
        resource_type="memory",
        resource_id=str(memory.id),
        details={"source": payload.source, "status": memory.security_status},
    )
    db.commit()
    db.refresh(memory)
    return memory


@router.get("/memory", response_model=list[MemoryRead])
def list_memory(
    agent_id: UUID | None = None,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> list[MemoryObject]:
    query = db.query(MemoryObject).filter(MemoryObject.org_id == principal.org_id)
    if agent_id:
        _agent_for_org(db, agent_id, principal.org_id)
        query = query.filter(MemoryObject.agent_id == agent_id)
    return query.order_by(desc(MemoryObject.modified_at)).limit(200).all()
