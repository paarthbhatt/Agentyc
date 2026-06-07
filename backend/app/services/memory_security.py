from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.security import sha256_text
from app.models import MemoryObject, TelemetryEvent
from app.services.detection import clamp, detect_memory_poisoning


def create_memory_object(db: Session, *, agent_id, source: str, content: str) -> MemoryObject:
    detection = detect_memory_poisoning(content)
    trust = clamp(70 - detection.score_penalty)
    status = "quarantined" if detection.indicators else "active"
    memory = MemoryObject(
        agent_id=agent_id,
        source=source,
        content_hash=sha256_text(content),
        preview=content[:280],
        trust_level=trust,
        security_status=status,
        indicators=detection.indicators,
    )
    db.add(memory)
    db.flush()
    db.add(
        TelemetryEvent(
            agent_id=agent_id,
            session_id="memory",
            event_type="memory.write",
            severity="high" if detection.indicators else "info",
            payload={"memory_id": str(memory.id), "source": source, "indicators": detection.indicators, "status": status},
            trust_score=trust,
            risk_score=100 - trust,
        )
    )
    db.commit()
    db.refresh(memory)
    return memory
