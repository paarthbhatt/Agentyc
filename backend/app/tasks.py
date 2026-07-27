from __future__ import annotations

import os
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.session import SessionLocal
from app.models import (
    Agent,
    BehaviorBaseline,
    Incident,
    IntegrationOutbox,
    TelemetryEvent,
)
from app.worker import celery_app

settings = get_settings()
OUTBOX_MAX_ATTEMPTS = max(1, int(os.getenv("OUTBOX_MAX_ATTEMPTS", "8")))
OUTBOX_BATCH_SIZE = max(1, int(os.getenv("OUTBOX_BATCH_SIZE", "100")))
OUTBOX_LEASE_SECONDS = max(30, int(os.getenv("OUTBOX_LEASE_SECONDS", "360")))
CORE_EVENT_TYPES = ("baseline.recalculate",)


class PermanentOutboxError(RuntimeError):
    pass


class RetryableOutboxError(RuntimeError):
    def __init__(self, message: str, attempts: int) -> None:
        super().__init__(message)
        self.attempts = attempts


def _as_uuid(value: str, field_name: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except (TypeError, ValueError) as exc:
        raise PermanentOutboxError(f"Invalid {field_name}: {value!r}") from exc


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _retry_delay(attempts: int) -> int:
    return min(300, 2 ** min(max(attempts, 1), 8))


def _lease_expired(event: IntegrationOutbox, now: datetime) -> bool:
    raw_value = (event.payload or {}).get("_delivery_lease_until")
    if not raw_value:
        return True
    try:
        lease_until = datetime.fromisoformat(str(raw_value))
        if lease_until.tzinfo is None:
            lease_until = lease_until.replace(tzinfo=timezone.utc)
        return lease_until <= now
    except (TypeError, ValueError):
        return True


def _set_delivery_lease(event: IntegrationOutbox, seconds: int) -> None:
    payload = dict(event.payload or {})
    payload["_delivery_lease_until"] = (
        datetime.now(timezone.utc) + timedelta(seconds=seconds)
    ).isoformat()
    event.payload = payload


def _recalculate_agent_baseline(db: Session, event: IntegrationOutbox) -> dict[str, Any]:
    agent_id = _as_uuid(event.aggregate_id, "agent id")
    agent = db.query(Agent).filter(Agent.id == agent_id, Agent.org_id == event.org_id).one_or_none()
    if agent is None:
        raise PermanentOutboxError("Agent does not exist in the outbox organization")

    telemetry = (
        db.query(TelemetryEvent)
        .filter(
            TelemetryEvent.org_id == event.org_id,
            TelemetryEvent.agent_id == agent_id,
        )
        .order_by(TelemetryEvent.occurred_at.asc())
        .all()
    )

    baseline = (
        db.query(BehaviorBaseline)
        .filter(
            BehaviorBaseline.org_id == event.org_id,
            BehaviorBaseline.agent_id == agent_id,
        )
        .one_or_none()
    )
    if baseline is None:
        baseline = BehaviorBaseline(org_id=event.org_id, agent_id=agent_id)
        db.add(baseline)

    tool_frequency: Counter[str] = Counter()
    action_frequency: Counter[str] = Counter()
    resource_frequency: Counter[str] = Counter()
    anomaly_count = 0

    for telemetry_event in telemetry:
        payload = telemetry_event.payload if isinstance(telemetry_event.payload, dict) else {}
        if payload.get("tool_name"):
            tool_frequency[str(payload["tool_name"])] += 1
        if payload.get("action"):
            action_frequency[str(payload["action"])] += 1
        if payload.get("resource"):
            resource_frequency[str(payload["resource"])] += 1
        if telemetry_event.event_type == "policy.violation" or telemetry_event.risk_score >= 70:
            anomaly_count += 1

    baseline.normal_tools = [name for name, _ in tool_frequency.most_common(5)]
    baseline.normal_actions = [name for name, _ in action_frequency.most_common(5)]
    baseline.normal_resources = [name for name, _ in resource_frequency.most_common(5)]
    baseline.event_count = len(telemetry)
    baseline.anomaly_count = anomaly_count
    baseline.last_score = telemetry[-1].risk_score if telemetry else 0

    return {
        "agent_id": str(agent_id),
        "events_processed": len(telemetry),
        "anomaly_count": anomaly_count,
    }


def _opensearch_client():
    from opensearchpy import OpenSearch

    username = os.getenv("OPENSEARCH_USERNAME", "")
    password = os.getenv("OPENSEARCH_PASSWORD", "")
    if not username or not password:
        raise PermanentOutboxError("OpenSearch credentials are not configured")

    verify_certs = _env_bool("OPENSEARCH_VERIFY_CERTS", True)
    if settings.is_production and not verify_certs:
        raise PermanentOutboxError("OPENSEARCH_VERIFY_CERTS cannot be disabled in production")

    options: dict[str, Any] = {
        "hosts": [settings.opensearch_url],
        "http_auth": (username, password),
        "http_compress": True,
        "use_ssl": settings.opensearch_url.startswith("https://"),
        "verify_certs": verify_certs,
        "ssl_assert_hostname": verify_certs,
    }
    ca_certs = os.getenv("OPENSEARCH_CA_CERTS", "").strip()
    if ca_certs:
        options["ca_certs"] = ca_certs
    return OpenSearch(**options)


def _neo4j_driver():
    from neo4j import GraphDatabase

    auth_value = os.getenv("NEO4J_AUTH", "")
    username, separator, password = auth_value.partition("/")
    if not separator or not username or not password:
        raise PermanentOutboxError("NEO4J_AUTH must use the username/password format")
    return GraphDatabase.driver(settings.neo4j_uri, auth=(username, password))


def _telemetry_for_outbox(db: Session, event: IntegrationOutbox) -> TelemetryEvent:
    telemetry_id = _as_uuid(event.aggregate_id, "telemetry id")
    telemetry = (
        db.query(TelemetryEvent)
        .filter(
            TelemetryEvent.id == telemetry_id,
            TelemetryEvent.org_id == event.org_id,
        )
        .one_or_none()
    )
    if telemetry is None:
        raise PermanentOutboxError("Telemetry event does not exist in the outbox organization")
    return telemetry


def _incident_for_outbox(db: Session, event: IntegrationOutbox) -> Incident:
    incident_id = _as_uuid(event.aggregate_id, "incident id")
    incident = (
        db.query(Incident)
        .filter(Incident.id == incident_id, Incident.org_id == event.org_id)
        .one_or_none()
    )
    if incident is None:
        raise PermanentOutboxError("Incident does not exist in the outbox organization")
    return incident


def _index_telemetry(telemetry: TelemetryEvent) -> None:
    client = _opensearch_client()
    try:
        org_id = str(telemetry.org_id)
        client.index(
            index="telemetry-events",
            id=f"{org_id}:{telemetry.id}",
            routing=org_id,
            body={
                "id": str(telemetry.id),
                "org_id": org_id,
                "agent_id": str(telemetry.agent_id),
                "session_id": telemetry.session_id,
                "event_type": telemetry.event_type,
                "severity": telemetry.severity,
                "risk_score": telemetry.risk_score,
                "trust_score": telemetry.trust_score,
                "client_event_id": telemetry.client_event_id,
                "payload": telemetry.payload or {},
                "occurred_at": telemetry.occurred_at.isoformat(),
            },
            refresh=False,
        )
    finally:
        client.close()


def _sync_telemetry_graph(telemetry: TelemetryEvent) -> None:
    driver = _neo4j_driver()
    try:
        agent = telemetry.agent
        identity_role = agent.identity.role if agent.identity else None
        payload = telemetry.payload if isinstance(telemetry.payload, dict) else {}
        org_id = str(telemetry.org_id)
        parameters = {
            "org_id": org_id,
            "agent_id": str(telemetry.agent_id),
            "agent_name": agent.name,
            "agent_role": identity_role,
            "agent_risk": agent.risk_score,
            "agent_trust": agent.trust_level,
            "event_id": str(telemetry.id),
            "event_type": telemetry.event_type,
            "event_risk": telemetry.risk_score,
            "event_trust": telemetry.trust_score,
            "occurred_at": telemetry.occurred_at.isoformat(),
        }
        with driver.session() as session:
            session.run(
                "MERGE (a:Agent {org_id: $org_id, id: $agent_id}) "
                "SET a.name = $agent_name, a.role = $agent_role, "
                "a.risk_score = $agent_risk, a.trust_level = $agent_trust "
                "MERGE (e:Event {org_id: $org_id, id: $event_id}) "
                "SET e.type = $event_type, e.risk_score = $event_risk, "
                "e.trust_score = $event_trust, e.occurred_at = $occurred_at "
                "MERGE (a)-[:EMITTED]->(e)",
                **parameters,
            ).consume()

            tool_name = payload.get("tool_name")
            if tool_name:
                session.run(
                    "MATCH (a:Agent {org_id: $org_id, id: $agent_id}) "
                    "MERGE (t:Tool {org_id: $org_id, name: $tool_name}) "
                    "MERGE (a)-[:USED_TOOL {event_id: $event_id}]->(t)",
                    org_id=org_id,
                    agent_id=str(telemetry.agent_id),
                    event_id=str(telemetry.id),
                    tool_name=str(tool_name),
                ).consume()

            resource = payload.get("resource")
            if resource:
                source_label = "Tool" if tool_name else "Agent"
                source_property = "name" if tool_name else "id"
                source_id = str(tool_name) if tool_name else str(telemetry.agent_id)
                session.run(
                    f"MATCH (s:{source_label} {{org_id: $org_id, {source_property}: $source_id}}) "
                    "MERGE (r:Resource {org_id: $org_id, name: $resource}) "
                    "MERGE (s)-[:ACCESSED_RESOURCE {event_id: $event_id}]->(r)",
                    org_id=org_id,
                    source_id=source_id,
                    event_id=str(telemetry.id),
                    resource=str(resource),
                ).consume()
    finally:
        driver.close()


def _index_incident(incident: Incident) -> None:
    client = _opensearch_client()
    try:
        org_id = str(incident.org_id)
        client.index(
            index="incidents",
            id=f"{org_id}:{incident.id}",
            routing=org_id,
            body={
                "id": str(incident.id),
                "org_id": org_id,
                "agent_id": str(incident.agent_id),
                "session_id": incident.session_id,
                "title": incident.title,
                "category": incident.category,
                "severity": incident.severity,
                "status": incident.status,
                "root_cause": incident.root_cause,
                "evidence": incident.evidence or {},
                "response_actions": incident.response_actions or [],
                "created_at": incident.created_at.isoformat(),
                "updated_at": incident.updated_at.isoformat(),
            },
            refresh=False,
        )
    finally:
        client.close()


def _sync_incident_graph(incident: Incident) -> None:
    driver = _neo4j_driver()
    try:
        agent = incident.agent
        org_id = str(incident.org_id)
        with driver.session() as session:
            session.run(
                "MERGE (a:Agent {org_id: $org_id, id: $agent_id}) "
                "SET a.name = $agent_name, a.risk_score = $agent_risk, "
                "a.trust_level = $agent_trust "
                "MERGE (i:Incident {org_id: $org_id, id: $incident_id}) "
                "SET i.title = $title, i.category = $category, "
                "i.severity = $severity, i.status = $status, "
                "i.created_at = $created_at, i.updated_at = $updated_at "
                "MERGE (a)-[:TRIGGERED_INCIDENT]->(i)",
                org_id=org_id,
                agent_id=str(incident.agent_id),
                agent_name=agent.name,
                agent_risk=agent.risk_score,
                agent_trust=agent.trust_level,
                incident_id=str(incident.id),
                title=incident.title,
                category=incident.category,
                severity=incident.severity,
                status=incident.status,
                created_at=incident.created_at.isoformat(),
                updated_at=incident.updated_at.isoformat(),
            ).consume()
    finally:
        driver.close()


def _handle_outbox_event(db: Session, event: IntegrationOutbox) -> dict[str, Any]:
    worker_mode = os.getenv("WORKER_MODE", "core").lower()
    if event.event_type == "baseline.recalculate":
        if worker_mode != "core":
            raise PermanentOutboxError("Baseline events must run on the core worker")
        return _recalculate_agent_baseline(db, event)

    if worker_mode != "analytics":
        raise PermanentOutboxError("Integration events must run on the analytics worker")

    if event.event_type == "telemetry.created":
        telemetry = _telemetry_for_outbox(db, event)
        _index_telemetry(telemetry)
        _sync_telemetry_graph(telemetry)
        return {"telemetry_id": str(telemetry.id), "destinations": ["opensearch", "neo4j"]}

    if event.event_type == "incident.created":
        incident = _incident_for_outbox(db, event)
        _index_incident(incident)
        _sync_incident_graph(incident)
        return {"incident_id": str(incident.id), "destinations": ["opensearch", "neo4j"]}

    raise PermanentOutboxError(f"Unsupported outbox event type: {event.event_type}")


def _process_outbox_event(outbox_id: str) -> dict[str, Any]:
    event_id = _as_uuid(outbox_id, "outbox id")
    db = SessionLocal()
    try:
        event = (
            db.execute(
                select(IntegrationOutbox)
                .where(IntegrationOutbox.id == event_id)
                .with_for_update(skip_locked=True)
            )
            .scalars()
            .one_or_none()
        )
        if event is None:
            return {"status": "skipped", "reason": "outbox event not found or locked"}
        if event.processed_at is not None:
            return {"status": "skipped", "reason": "already processed"}
        if event.attempts >= OUTBOX_MAX_ATTEMPTS:
            return {"status": "failed", "reason": "retry limit reached"}

        event.attempts += 1
        try:
            result = _handle_outbox_event(db, event)
        except PermanentOutboxError as exc:
            event.attempts = OUTBOX_MAX_ATTEMPTS
            event.last_error = str(exc)[:4000]
            db.commit()
            return {"status": "failed", "reason": str(exc), "permanent": True}
        except Exception as exc:
            delay = _retry_delay(event.attempts)
            event.last_error = f"{type(exc).__name__}: {exc}"[:4000]
            _set_delivery_lease(event, delay + 60)
            attempts = event.attempts
            db.commit()
            raise RetryableOutboxError(str(exc), attempts) from exc

        event.processed_at = datetime.now(timezone.utc)
        event.last_error = None
        db.commit()
        return {"status": "processed", "outbox_id": outbox_id, **result}
    except RetryableOutboxError:
        raise
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def _dispatch_pending(*, analytics: bool) -> dict[str, int]:
    db = SessionLocal()
    selected: list[str] = []
    now = datetime.now(timezone.utc)
    try:
        event_filter = (
            IntegrationOutbox.event_type.notin_(CORE_EVENT_TYPES)
            if analytics
            else IntegrationOutbox.event_type.in_(CORE_EVENT_TYPES)
        )
        events = (
            db.execute(
                select(IntegrationOutbox)
                .where(
                    IntegrationOutbox.processed_at.is_(None),
                    IntegrationOutbox.attempts < OUTBOX_MAX_ATTEMPTS,
                    event_filter,
                )
                .order_by(IntegrationOutbox.created_at.asc())
                .limit(OUTBOX_BATCH_SIZE)
                .with_for_update(skip_locked=True)
            )
            .scalars()
            .all()
        )
        for event in events:
            if not _lease_expired(event, now):
                continue
            _set_delivery_lease(event, OUTBOX_LEASE_SECONDS)
            selected.append(str(event.id))
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

    queue = "analytics" if analytics else "core"
    for event_id in selected:
        process_integration_outbox_event.apply_async(args=[event_id], queue=queue)
    return {"dispatched": len(selected)}


@celery_app.task(name="app.tasks.dispatch_core_outbox", acks_late=True)
def dispatch_core_outbox() -> dict[str, int]:
    return _dispatch_pending(analytics=False)


@celery_app.task(name="app.tasks.dispatch_analytics_outbox", acks_late=True)
def dispatch_analytics_outbox() -> dict[str, int]:
    return _dispatch_pending(analytics=True)


@celery_app.task(
    bind=True,
    name="app.tasks.process_integration_outbox_event",
    acks_late=True,
    reject_on_worker_lost=True,
    max_retries=OUTBOX_MAX_ATTEMPTS,
)
def process_integration_outbox_event(self, outbox_id: str) -> dict[str, Any]:
    try:
        return _process_outbox_event(outbox_id)
    except RetryableOutboxError as exc:
        if exc.attempts >= OUTBOX_MAX_ATTEMPTS:
            return {
                "status": "failed",
                "reason": str(exc),
                "attempts": exc.attempts,
            }
        raise self.retry(exc=exc, countdown=_retry_delay(exc.attempts)) from exc
