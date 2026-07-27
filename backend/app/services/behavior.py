from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import BehaviorBaseline, TelemetryEvent
from app.services.detection import clamp


def _append_unique(values: list[str], value: str, limit: int = 50) -> list[str]:
    if not value:
        return values
    merged = list(dict.fromkeys([*values, value]))
    return merged[-limit:]


def update_behavior_baseline(db: Session, event: TelemetryEvent) -> BehaviorBaseline:
    baseline = (
        db.query(BehaviorBaseline)
        .filter(
            BehaviorBaseline.org_id == event.org_id,
            BehaviorBaseline.agent_id == event.agent_id,
        )
        .one_or_none()
    )
    if baseline is None:
        baseline = BehaviorBaseline(org_id=event.org_id, agent_id=event.agent_id)
        db.add(baseline)
        db.flush()

    payload = event.payload or {}
    tool_name = str(payload.get("tool_name", ""))
    action = str(payload.get("action", ""))
    resource = str(payload.get("resource", ""))

    anomaly = 0
    if baseline.event_count >= 10:
        if tool_name and tool_name not in baseline.normal_tools:
            anomaly += 30
        if action and action not in baseline.normal_actions:
            anomaly += 20
        if resource and resource not in baseline.normal_resources:
            anomaly += 25
        if event.risk_score >= 70:
            anomaly += 25

    baseline.normal_tools = _append_unique(baseline.normal_tools, tool_name)
    baseline.normal_actions = _append_unique(baseline.normal_actions, action)
    baseline.normal_resources = _append_unique(baseline.normal_resources, resource)
    baseline.event_count += 1
    baseline.last_score = clamp(anomaly)
    if anomaly >= 50:
        baseline.anomaly_count += 1
    return baseline
