from __future__ import annotations

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.api.auth import Principal, get_current_principal, require_csrf
from app.api.routers.common import _audit
from app.db.session import get_db
from app.models import ThreatIntelIndicator
from app.schemas import ThreatIntelCreate, ThreatIntelRead

router = APIRouter()


@router.post(
    "/threats/indicators", response_model=ThreatIntelRead, status_code=status.HTTP_201_CREATED
)
def create_threat_indicator(
    payload: ThreatIntelCreate,
    request: Request,
    principal: Principal = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> ThreatIntelIndicator:
    indicator = ThreatIntelIndicator(org_id=principal.org_id, **payload.model_dump())
    db.add(indicator)
    db.flush()
    _audit(
        db,
        principal,
        request,
        action="threat_indicator.create",
        resource_type="threat_indicator",
        resource_id=str(indicator.id),
    )
    db.commit()
    db.refresh(indicator)
    return indicator


@router.get("/threats/indicators", response_model=list[ThreatIntelRead])
def list_threat_indicators(
    active: bool | None = None,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> list[ThreatIntelIndicator]:
    query = db.query(ThreatIntelIndicator).filter(ThreatIntelIndicator.org_id == principal.org_id)
    if active is not None:
        query = query.filter(ThreatIntelIndicator.active == active)
    return query.order_by(desc(ThreatIntelIndicator.created_at)).limit(500).all()
