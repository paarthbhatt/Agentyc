from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.auth import Principal, get_current_principal
from app.api.routers.common import _agent_for_org
from app.db.session import get_db
from app.models import BehaviorBaseline
from app.schemas import BehaviorBaselineRead

router = APIRouter()


@router.get("/baselines/agents/{agent_id}", response_model=BehaviorBaselineRead)
def get_behavior_baseline(
    agent_id: UUID,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> BehaviorBaseline:
    _agent_for_org(db, agent_id, principal.org_id)
    baseline = (
        db.query(BehaviorBaseline)
        .filter(BehaviorBaseline.org_id == principal.org_id, BehaviorBaseline.agent_id == agent_id)
        .one_or_none()
    )
    if baseline is None:
        baseline = BehaviorBaseline(org_id=principal.org_id, agent_id=agent_id)
        db.add(baseline)
        db.commit()
        db.refresh(baseline)
    return baseline
