from __future__ import annotations

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.api.auth import Principal, get_current_principal, require_csrf
from app.api.routers.common import _agent_for_org, _audit
from app.db.session import get_db
from app.models import RedTeamScenario
from app.schemas import RedTeamGenerateRequest, RedTeamScenarioRead
from app.services.red_team import generate_red_team_scenarios

router = APIRouter()


@router.post(
    "/redteam/generate",
    response_model=list[RedTeamScenarioRead],
    status_code=status.HTTP_201_CREATED,
)
def generate_redteam(
    payload: RedTeamGenerateRequest,
    request: Request,
    principal: Principal = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> list[RedTeamScenario]:
    if payload.agent_id:
        _agent_for_org(db, payload.agent_id, principal.org_id)
    scenarios = generate_red_team_scenarios(
        org_id=principal.org_id,
        agent_id=payload.agent_id,
        goal=payload.goal,
        tools=payload.tools,
        resources=payload.resources,
    )
    db.add_all(scenarios)
    db.flush()
    _audit(
        db,
        principal,
        request,
        action="redteam.generate",
        resource_type="redteam_scenario",
        resource_id=",".join(str(item.id) for item in scenarios),
        details={"count": len(scenarios)},
    )
    db.commit()
    for scenario in scenarios:
        db.refresh(scenario)
    return scenarios


@router.get("/redteam/scenarios", response_model=list[RedTeamScenarioRead])
def list_redteam_scenarios(
    principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)
) -> list[RedTeamScenario]:
    return (
        db.query(RedTeamScenario)
        .filter(RedTeamScenario.org_id == principal.org_id)
        .order_by(desc(RedTeamScenario.created_at))
        .limit(200)
        .all()
    )
