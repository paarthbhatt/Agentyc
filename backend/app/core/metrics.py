from __future__ import annotations

from collections import Counter
from threading import Lock

_lock = Lock()
_http_requests: Counter[tuple[str, str, str]] = Counter()
_http_duration_ms: Counter[tuple[str, str]] = Counter()
_decisions: Counter[str] = Counter()


def record_http(method: str, path: str, status_code: int, duration_ms: float) -> None:
    normalized_path = path if path in {"/", "/ready"} else path.split("?", 1)[0]
    status_class = f"{status_code // 100}xx"
    with _lock:
        _http_requests[(method, normalized_path, status_class)] += 1
        _http_duration_ms[(method, normalized_path)] += duration_ms


def record_decision(decision: str) -> None:
    with _lock:
        _decisions[decision] += 1


def render_prometheus() -> str:
    lines = [
        "# HELP agent_sentinel_http_requests_total HTTP requests processed.",
        "# TYPE agent_sentinel_http_requests_total counter",
    ]
    with _lock:
        for (method, path, status_class), value in sorted(_http_requests.items()):
            lines.append(
                f'agent_sentinel_http_requests_total{{method="{method}",path="{path}",status_class="{status_class}"}} {value}'
            )
        lines.extend(
            [
                "# HELP agent_sentinel_http_duration_ms_total Cumulative request latency in milliseconds.",
                "# TYPE agent_sentinel_http_duration_ms_total counter",
            ]
        )
        for (method, path), value in sorted(_http_duration_ms.items()):
            lines.append(
                f'agent_sentinel_http_duration_ms_total{{method="{method}",path="{path}"}} {value:.3f}'
            )
        lines.extend(
            [
                "# HELP agent_sentinel_enforcement_decisions_total Enforcement decisions by outcome.",
                "# TYPE agent_sentinel_enforcement_decisions_total counter",
            ]
        )
        for decision, value in sorted(_decisions.items()):
            lines.append(
                f'agent_sentinel_enforcement_decisions_total{{decision="{decision}"}} {value}'
            )
    return "\n".join(lines) + "\n"
