from __future__ import annotations

import asyncio
import json
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from app.api.auth import Principal, get_current_principal
from app.db.session import SessionLocal
from app.models import TelemetryEvent
from app.schemas import TelemetryEventRead

router = APIRouter()


@router.get("/telemetry/stream")
def telemetry_stream(
    request: Request,
    agent_id: UUID | None = None,
    poll_seconds: float = 1.5,
    principal: Principal = Depends(get_current_principal),
) -> StreamingResponse:
    org_id = principal.org_id

    async def event_generator():
        last_seen = None
        while not await request.is_disconnected():
            db = SessionLocal()
            try:
                query = db.query(TelemetryEvent).filter(TelemetryEvent.org_id == org_id)
                if agent_id:
                    query = query.filter(TelemetryEvent.agent_id == agent_id)
                if last_seen:
                    query = query.filter(TelemetryEvent.occurred_at > last_seen)
                events = query.order_by(TelemetryEvent.occurred_at).limit(50).all()
                for event in events:
                    last_seen = event.occurred_at
                    payload = TelemetryEventRead.model_validate(event).model_dump(mode="json")
                    yield "data: " + json.dumps(payload) + "\n\n"
            finally:
                db.close()
            await asyncio.sleep(max(0.5, min(poll_seconds, 10)))

    return StreamingResponse(
        event_generator(), media_type="text/event-stream", headers={"Cache-Control": "no-store"}
    )
