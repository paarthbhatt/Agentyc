from __future__ import annotations

from fastapi import APIRouter

from app.api.routers import (
    agents,
    baselines,
    dashboard,
    enforcement,
    health,
    incidents,
    insights,
    mcp,
    memory,
    multi_agent,
    policies,
    redteam,
    sandbox,
    streaming,
    telemetry,
    threat_intel,
    tools,
)

router = APIRouter()

for domain_router in (
    health.router,
    agents.router,
    telemetry.router,
    enforcement.router,
    tools.router,
    memory.router,
    incidents.router,
    dashboard.router,
    policies.router,
    insights.router,
    streaming.router,
    mcp.router,
    multi_agent.router,
    sandbox.router,
    baselines.router,
    redteam.router,
    threat_intel.router,
):
    router.include_router(domain_router)
