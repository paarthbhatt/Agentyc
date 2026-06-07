from __future__ import annotations

from app.models import ThreatIntelIndicator


def match_indicators(text: str, indicators: list[ThreatIntelIndicator]) -> list[ThreatIntelIndicator]:
    normalized = text.lower()
    return [indicator for indicator in indicators if indicator.active and indicator.value.lower() in normalized]
