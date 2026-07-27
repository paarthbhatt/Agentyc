from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.auth import Principal, get_agent_principal
from app.api.routers.common import _assert_agent
from app.db.session import get_db
from app.schemas import EnforcementDecision, EnforcementRequest
from app.services.firewall import evaluate_and_record

router = APIRouter()


@router.post("/enforce/action", response_model=EnforcementDecision)
def enforce_action(
    payload: EnforcementRequest,
    principal: Principal = Depends(get_agent_principal),
    db: Session = Depends(get_db),
) -> EnforcementDecision:
    _assert_agent(principal, payload.agent_id)
    try:
        result = evaluate_and_record(db, payload, org_id=principal.org_id)
        db.commit()
        return result
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except IntegrityError:
        db.rollback()
        if payload.action_id:
            return evaluate_and_record(db, payload, org_id=principal.org_id)
        raise
