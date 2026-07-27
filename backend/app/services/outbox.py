from __future__ import annotations

from uuid import UUID

from sqlalchemy.orm import Session

from app.models import IntegrationOutbox


def queue_integration(
    db: Session,
    *,
    org_id: UUID,
    event_type: str,
    aggregate_type: str,
    aggregate_id: str,
    payload: dict | None = None,
) -> IntegrationOutbox:
    event = IntegrationOutbox(
        org_id=org_id,
        event_type=event_type,
        aggregate_type=aggregate_type,
        aggregate_id=aggregate_id,
        payload=payload or {},
    )
    db.add(event)
    return event
