from __future__ import annotations

import json
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.security import sha256_text
from app.models import AuditLog


def record_audit(
    db: Session,
    *,
    org_id: UUID,
    actor_type: str,
    actor_id: str | None,
    action: str,
    resource_type: str,
    resource_id: str,
    details: dict | None = None,
    user_id: UUID | None = None,
    request_id: str | None = None,
) -> AuditLog:
    if db.bind and db.bind.dialect.name == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:lock_key))"),
            {"lock_key": f"audit:{org_id}"},
        )
    previous = (
        db.query(AuditLog)
        .filter(AuditLog.org_id == org_id)
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .with_for_update()
        .first()
    )
    previous_hash = previous.record_hash if previous else None
    body = {
        "org_id": str(org_id),
        "actor_type": actor_type,
        "actor_id": actor_id,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "details": details or {},
        "request_id": request_id,
        "previous_hash": previous_hash,
    }
    entry = AuditLog(
        org_id=org_id,
        user_id=user_id,
        actor_type=actor_type,
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details or {},
        request_id=request_id,
        previous_hash=previous_hash,
        record_hash=sha256_text(json.dumps(body, sort_keys=True, separators=(",", ":"))),
    )
    db.add(entry)
    return entry


def verify_audit_chain(db: Session, *, org_id: UUID) -> tuple[bool, str | None]:
    entries = (
        db.query(AuditLog)
        .filter(AuditLog.org_id == org_id)
        .order_by(AuditLog.created_at, AuditLog.id)
        .all()
    )
    expected_previous = None
    for entry in entries:
        body = {
            "org_id": str(entry.org_id),
            "actor_type": entry.actor_type,
            "actor_id": entry.actor_id,
            "action": entry.action,
            "resource_type": entry.resource_type,
            "resource_id": entry.resource_id,
            "details": entry.details or {},
            "request_id": entry.request_id,
            "previous_hash": expected_previous,
        }
        expected_hash = sha256_text(json.dumps(body, sort_keys=True, separators=(",", ":")))
        if entry.previous_hash != expected_previous or entry.record_hash != expected_hash:
            return False, str(entry.id)
        expected_previous = entry.record_hash
    return True, None
