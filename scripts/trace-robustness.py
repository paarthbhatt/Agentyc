#!/usr/bin/env python3
"""Run a bounded, in-process robustness review of Agentyc trace replay.

The harness exercises the real telemetry and replay functions when the locked
backend dependencies are available.  It deliberately does not import
``app.main`` or start a server, worker, broker, database, or tool runtime.  A
fresh in-memory SQLite database is used for every case and each case is
rolled back.  Network, process, unexpected file-I/O, and replay-write audit
events are denied.  Mutation inputs and reproductions are kept below
``/tmp/omnirush`` only.

Example::

    python scripts/trace-robustness.py --mutations 2000 --seed 20261011

The script exits 0 for a completed audit, 1 when ``--fail-on-findings`` is
used and a target failure or synthetic-secret disclosure was observed, and 2
when the bounded harness could not complete or the runtime dependencies were
not installed.  Missing dependencies are reported cleanly so a review never
falls back to network installation.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.metadata
import json
import math
import os
import random
import resource
import signal
import sys
import tempfile
import time
import traceback
import uuid
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
TMP_ROOT = Path("/tmp/omnirush")
AGENT_ID = uuid.UUID("00000000-0000-4000-8000-000000000001")
ORG_ID = uuid.UUID("00000000-0000-4000-8000-000000000002")
OTHER_ORG_ID = uuid.UUID("00000000-0000-4000-8000-000000000003")
INCIDENT_ID = uuid.UUID("00000000-0000-4000-8000-000000000004")
EVENT_ID = uuid.UUID("00000000-0000-4000-8000-000000000005")
SESSION = "trace-robustness-session"
CANARIES = (
    "sk-audit-synthetic-20261011-0123456789",
    "audit-token-20261011-abcdefghijklmnopqrstuvwxyz",
    "audit-password-20261011-do-not-disclose",
)

NETWORK_EVENTS = {
    "socket.__new__",
    "socket.connect",
    "socket.getaddrinfo",
    "socket.gethostbyname",
    "socket.gethostbyaddr",
    "socket.sendto",
    "socket.sendmsg",
}
PROCESS_EVENTS = {
    "subprocess.Popen",
    "os.system",
    "os.exec",
    "os.posix_spawn",
    "os.spawn",
    "os.fork",
    "os.forkpty",
    "os.startfile",
    "pty.spawn",
}


class SafetyViolation(RuntimeError):
    """Raised when the target attempts an operation outside the audit scope."""


class CaseTimeout(TimeoutError):
    """Raised when one input exceeds its wall-clock budget."""


class HarnessLimit(ValueError):
    """Raised when a candidate is rejected by an explicit harness bound."""


@dataclass(frozen=True)
class Case:
    mode: str
    family: str
    label: str
    raw: bytes


@dataclass
class Stats:
    attempted: int = 0
    completed: int = 0
    outcomes: Counter = field(default_factory=Counter)
    families: Counter = field(default_factory=Counter)
    secrets: Counter = field(default_factory=Counter)
    failures: Counter = field(default_factory=Counter)
    first_failure: dict[str, dict[str, str]] = field(default_factory=dict)
    max_bytes: int = 0
    max_depth: int = 0
    max_case_ms: float = 0.0
    duplicate_keys: int = 0
    controls: dict[str, Any] = field(default_factory=dict)


class Guards:
    """Deny external effects and writes while the target is under test."""

    def __init__(self) -> None:
        self.active = False
        self.replaying = False
        self.attempts: Counter = Counter()

    @staticmethod
    def _allowed_runtime_read(args: tuple[Any, ...]) -> bool:
        """Allow lazy interpreter imports without allowing trace file access."""
        if not args:
            return False
        path = args[0]
        if not isinstance(path, (str, bytes)):
            return False
        try:
            path_text = os.fsdecode(path)
        except (TypeError, ValueError):
            return False
        mode = args[1] if len(args) > 1 and isinstance(args[1], str) else ""
        flags = args[2] if len(args) > 2 and isinstance(args[2], int) else 0
        write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
        if any(marker in mode for marker in ("w", "a", "x", "+")) or flags & write_flags:
            return False
        if "MUST-NOT-EXIST" in path_text or path_text.startswith(str(TMP_ROOT)):
            return False
        candidate = Path(path_text)
        roots = {Path(sys.prefix), Path(sys.base_prefix), Path(sys.exec_prefix)}
        return any(candidate.is_relative_to(root) for root in roots)

    def audit(self, event: str, args: tuple[Any, ...]) -> None:
        kind = None
        if event in NETWORK_EVENTS:
            kind = "network"
        elif event in PROCESS_EVENTS:
            kind = "process"
        elif event == "open" and self.active and not self._allowed_runtime_read(args):
            kind = "file_io"
        if kind:
            self.attempts[kind] += 1
            frames = []
            frame = sys._getframe(1)
            while frame is not None and len(frames) < 8:
                frames.append(f"{Path(frame.f_code.co_filename).name}:{frame.f_lineno}")
                frame = frame.f_back
            detail = safe_detail(args[0]) if event == "open" and args else ""
            raise SafetyViolation(f"blocked {kind} event: {event} {detail}; sites={','.join(frames)}")

    def sql(self, conn, cursor, statement, parameters, context, executemany) -> None:
        del conn, cursor, parameters, context, executemany
        if self.replaying and not statement.lstrip().upper().startswith(("SELECT", "PRAGMA")):
            self.attempts["replay_write"] += 1
            raise SafetyViolation("replay attempted a non-SELECT SQL statement")

    def self_check(self) -> None:
        for event in ("socket.connect", "subprocess.Popen", "open"):
            self.active = True
            try:
                sys.audit(event, None)
            except SafetyViolation:
                pass
            else:
                raise SafetyViolation(f"guard self-check failed: {event}")
            finally:
                self.active = False
        self.attempts.clear()


def encode(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("utf-8")


def capture_document(payload: Any = None) -> dict[str, Any]:
    return {
        "agent_id": str(AGENT_ID),
        "session_id": SESSION,
        "event_type": "trace.audit",
        "severity": "info",
        "trust_score": 70,
        "risk_score": 20,
        "payload": {} if payload is None else payload,
    }


def has_canary(raw: bytes | str) -> bool:
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="replace")
    return any(canary.encode("ascii") in raw for canary in CANARIES)


def redact(value: str) -> str:
    for canary in CANARIES:
        value = value.replace(canary, "[SYNTHETIC-SECRET]")
    return value


def safe_detail(value: Any) -> str:
    return redact(str(value))[:240].replace("\n", " ")


def nesting_depth(raw: bytes) -> int:
    """Return a bounded diagnostic depth without interpreting quoted braces."""
    depth = peak = 0
    quoted = escaped = False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            peak = max(peak, depth)
        elif byte in (93, 125):
            depth = max(0, depth - 1)
    return peak


def bound_nodes(value: Any, maximum: int) -> None:
    """Count parsed containers iteratively so the harness does not recurse."""
    stack = [value]
    count = 0
    while stack:
        current = stack.pop()
        count += 1
        if count > maximum:
            raise HarnessLimit("parsed input exceeds harness node cap")
        if isinstance(current, dict):
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)


def duplicate_count(raw: bytes) -> int:
    duplicates = 0

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        nonlocal duplicates
        seen: set[str] = set()
        result: dict[str, Any] = {}
        for key, value in items:
            if key in seen:
                duplicates += 1
            seen.add(key)
            result[key] = value
        return result

    json.loads(raw, object_pairs_hook=pairs)
    return duplicates


def deep_capture(depth: int) -> bytes:
    raw = encode(capture_document())
    fragment = b'{"n":' * depth + b'"leaf"' + b"}" * depth
    return raw.replace(b'"payload":{}', b'"payload":{"deep":' + fragment + b"}")


def duplicate_capture() -> bytes:
    raw = encode(capture_document({"nested": {"token": "last"}}))
    raw = raw.replace(b'"severity":"info"', b'"severity":"low","severity":"info"')
    return raw.replace(b'"nested":{"token":"last"}', b'"nested":{"token":"first","token":"last"}')


def corpus() -> list[Case]:
    secret_payload = {
        "api_key": CANARIES[0],
        "headers": {"Authorization": f"Bearer {CANARIES[1]}"},
        "nested": [{"password": CANARIES[2]}],
        "message": f"token={CANARIES[1]}",
    }
    effects = {
        "tool_name": "shell.execute",
        "decision": "allow",
        "arguments": {
            "command": "touch /tmp/omnirush/trace-robustness-MUST-NOT-EXIST",
            "url": "https://example.invalid/never-contact",
            "method": "POST",
            "body": {"token": CANARIES[1]},
        },
        "python": "__import__('os').system('false')",
        "template": "{{ config.items() }}",
        "html": "<script>fetch('https://example.invalid/')</script>",
    }
    extra = capture_document({"known": "value", "nested_extra": {"unexpected": [1, 2, 3]}})
    extra["unexpected_top_level"] = {"should": "be ignored by the envelope schema"}
    cases = [
        Case("capture", "valid", "valid-empty", encode(capture_document())),
        Case("capture", "extra-fields", "top-level-and-nested-extra", encode(extra)),
        Case("capture", "secret-payload", "nested-secrets", encode(capture_document(secret_payload))),
        Case("capture", "side-effect-arguments", "effect-shaped-data", encode(capture_document(effects))),
        Case("capture", "unicode-escapes", "unicode-and-escaped-control", encode(capture_document({
            "snowman": "☃",
            "escaped": "line\nquote\"slash\\",
            "combining": "e\u0301",
        }))),
        Case("capture", "duplicate-keys", "duplicate-top-level-and-nested", duplicate_capture()),
    ]
    for raw in (b"", b"{", b'{"payload":', b'{"payload":{"x":"cut', b"\xff\xfe", b"{} trailing"):
        cases.append(Case("capture", "truncated-json", f"malformed-{len(cases)}", raw))
    for value, label in (
        (None, "null"),
        ([], "array"),
        ("not-an-object", "string"),
        (1, "integer"),
        (True, "boolean"),
    ):
        document = capture_document()
        document["payload"] = value
        cases.append(Case("capture", "wrong-types", f"payload-{label}", encode(document)))
    wrong_envelope = capture_document()
    wrong_envelope["agent_id"] = []
    wrong_envelope["session_id"] = {"not": "a string"}
    cases.append(Case("capture", "wrong-types", "wrong-envelope-fields", encode(wrong_envelope)))
    for value, label in ((float("nan"), "nan"), (float("inf"), "infinity"), ("\ud800", "surrogate")):
        cases.append(Case("capture", "nonstandard-values", label, encode(capture_document({"value": value}))))
    for length in (4_096, 262_144, 524_288):
        cases.append(Case(
            "capture",
            "huge-strings",
            f"blob-{length}",
            encode(capture_document({"blob": "x" * length, "api_key": CANARIES[0]})),
        ))
    cases.append(Case("capture", "wide-arrays", "items-20000", encode(capture_document({"items": [0] * 20_000}))))
    for depth in (32, 128, 256, 512, 900, 1100):
        cases.append(Case("capture", "deep-nesting", f"depth-{depth}", deep_capture(depth)))
    invalid = capture_document(secret_payload)
    invalid["severity"] = CANARIES[1]
    cases.append(Case("capture", "secret-in-validation-error", "secret-in-invalid-severity", encode(invalid)))
    for value, label in (
        (None, "null"),
        ([], "array"),
        ("bad", "string"),
        (1, "integer"),
        (secret_payload, "secret"),
    ):
        cases.append(Case("stored_event", "corrupt-stored-payload", f"stored-payload-{label}", encode({"payload": value})))
        cases.append(Case("stored_incident", "corrupt-stored-evidence", f"stored-evidence-{label}", encode({"evidence": value})))
    for value, label in (
        (None, "null"),
        ([], "array"),
        ("bad", "string"),
        (1, "integer"),
        ([["nested"]], "nested"),
    ):
        cases.append(Case("stored_incident", "corrupt-response-actions", f"actions-{label}", encode({"response_actions": value})))
    for raw in (b"{", b'{"api_key":"cut', b"[1,"):
        cases.append(Case("stored_raw", "truncated-storage", f"stored-truncated-{len(cases)}", raw))
    return cases


def mutation(rng: random.Random, index: int, seeds: list[Case]) -> Case:
    """Generate one bounded mutation without growing a corpus or history."""
    base = seeds[rng.randrange(len(seeds))]
    operation = rng.randrange(12)
    raw = base.raw
    if operation == 0:
        raw = raw[:rng.randrange(len(raw) + 1)]
        family = "mutated-truncation"
    elif operation == 1:
        position = rng.randrange(len(raw) + 1)
        raw = raw[:position] + rng.choice((b"\x00", b"\xff", b"}", b",", b'"')) + raw[position:]
        family = "mutated-byte-insert"
    elif operation == 2:
        raw += rng.choice((b" trailing", b"]", b",{}"))
        family = "mutated-suffix"
    else:
        try:
            document = json.loads(raw)
        except (ValueError, RecursionError, UnicodeDecodeError):
            return Case(base.mode, base.family, f"mutation-{index}", raw)
        if not isinstance(document, dict):
            document = capture_document()
        if operation == 3:
            document["unexpected"] = {"nested": [CANARIES[0], "x"]}
            family = "mutated-extra-fields"
        elif operation == 4:
            field_name = "payload" if base.mode == "capture" else rng.choice(list(document) or ["payload"])
            document[field_name] = rng.choice((None, [], 1, True, CANARIES[0], {"token": CANARIES[1]}))
            family = "mutated-wrong-types"
        elif operation == 5:
            document["payload"] = {"api_key": CANARIES[0], "nested": {"token": CANARIES[1]}}
            family = "mutated-secret-insert"
        elif operation == 6:
            field_name = "payload" if base.mode == "capture" else rng.choice(list(document) or ["payload"])
            document[field_name] = {"value": rng.choice((float("nan"), float("inf"), "\ud800", -1))}
            family = "mutated-nonstandard-values"
        elif operation == 7:
            document["payload"] = {"tool_name": "http.request", "arguments": {
                "url": "https://example.invalid/", "command": "false",
            }}
            family = "mutated-side-effect-arguments"
        elif operation == 8:
            document["payload"] = {"blob": "x" * rng.choice((4_096, 65_536, 262_144))}
            family = "mutated-huge-strings"
        elif operation == 9:
            document["payload"] = {"items": [0] * rng.choice((128, 2_048, 10_000))}
            family = "mutated-wide-arrays"
        elif operation == 10:
            document["payload"] = {"unicode": "☃\n\u0301", "token": CANARIES[1]}
            family = "mutated-unicode-escapes"
        else:
            document["payload"] = {"duplicate": "last"}
            raw = encode(document).replace(b'"payload":{"duplicate":"last"}', b'"payload":{"duplicate":"first","duplicate":"last"}')
            family = "mutated-duplicate-keys"
        if raw == base.raw:
            try:
                raw = encode(document)
            except (RecursionError, ValueError):
                return Case(base.mode, base.family, f"mutation-{index}", base.raw)
    return Case(base.mode, family, f"mutation-{index}", raw)


def configure_test_environment() -> None:
    """Set only child-process environment variables; never edit project config."""
    sys.dont_write_bytecode = True
    os.environ.update({
        "ENVIRONMENT": "test",
        "DATABASE_URL": "sqlite://",
        "ENABLE_DEMO_SEED": "false",
        "RATE_LIMIT_ENABLED": "false",
        "AGENT_SENTINEL_ALLOW_OPEN_REGISTER": "false",
        "PYTHON_DOTENV_DISABLED": "1",
        "JWT_SECRET_KEY": "audit-synthetic-jwt-not-for-deployment",
        "API_KEY_PEPPER": "audit-synthetic-pepper-not-for-deployment",
        "ADMIN_API_KEY": "audit-synthetic-admin-not-for-deployment",
    })
    sys.path[:0] = [str(ROOT / "backend"), str(ROOT / "sdk/python")]


class Runtime:
    """Import only data-handling modules and run them against fresh SQLite."""

    def __init__(self, guards: Guards) -> None:
        from datetime import datetime, timezone

        from app.api.auth import Principal
        from app.api.routers import incidents, telemetry
        from app.db.session import Base
        from app.db.session import engine as configured_engine
        from app.models import Agent, Incident, Organization, TelemetryEvent, User
        from app.schemas import TelemetryEventCreate, TelemetryEventRead
        from fastapi.encoders import jsonable_encoder
        from pydantic import TypeAdapter, ValidationError
        from sqlalchemy import create_engine, event
        from sqlalchemy.orm import Session as DBSession
        from starlette.responses import JSONResponse

        class RollbackSession(DBSession):
            def commit(self) -> None:
                self.flush()

        if str(configured_engine.url) != "sqlite://":
            raise SafetyViolation("test configuration did not resolve to in-memory SQLite")
        self.Session = RollbackSession
        self.DBSession = DBSession
        self.telemetry = telemetry
        self.incidents = incidents
        self.Event = TelemetryEvent
        self.Incident = Incident
        self.Create = TelemetryEventCreate
        self.Read = TelemetryEventRead
        self.list_adapter = TypeAdapter(list[TelemetryEventRead])
        self.ValidationError = ValidationError
        self.JSONResponse = JSONResponse
        self.jsonable_encoder = jsonable_encoder
        self.guards = guards
        self.now = datetime(2026, 10, 11, tzinfo=timezone.utc)
        self.engine = create_engine("sqlite://")
        event.listen(self.engine, "before_cursor_execute", guards.sql)
        Base.metadata.create_all(self.engine)
        self.user_principal = Principal("user", ORG_ID, "owner")
        self.agent_principal = Principal("agent", ORG_ID, "agent", agent_id=AGENT_ID)
        self.other_principal = Principal("user", OTHER_ORG_ID, "owner")
        with DBSession(self.engine) as db:
            user = User(id=uuid.UUID(int=10), email="audit@example.invalid", password_hash="unused")
            db.add(user)
            db.flush()
            db.add_all([
                Organization(id=ORG_ID, name="Audit", slug="trace-audit", owner_id=user.id),
                Organization(id=OTHER_ORG_ID, name="Other", slug="trace-other", owner_id=user.id),
            ])
            db.flush()
            db.add(Agent(id=AGENT_ID, org_id=ORG_ID, name="Trace audit", api_key_hash="unused"))
            db.flush()
            db.add(Incident(
                id=INCIDENT_ID,
                org_id=ORG_ID,
                agent_id=AGENT_ID,
                session_id=SESSION,
                title="Audit fixture",
                category="audit",
                severity="info",
                root_cause="fixture",
                evidence={},
                response_actions=[],
                created_at=self.now,
                updated_at=self.now,
            ))
            db.commit()

    def event_values(self, event_id: uuid.UUID = EVENT_ID) -> dict[str, Any]:
        return {
            "id": event_id,
            "org_id": ORG_ID,
            "agent_id": AGENT_ID,
            "session_id": SESSION,
            "event_type": "trace.audit",
            "severity": "info",
            "payload": {},
            "trust_score": 70,
            "risk_score": 20,
            "client_event_id": None,
            "occurred_at": self.now,
        }

    def stored_case(self, case: Case, document: Any, db) -> None:
        if case.mode == "stored_incident":
            allowed = {"evidence", "response_actions", "title", "root_cause"}
            values = {key: value for key, value in document.items() if key in allowed}
            db.execute(self.Incident.__table__.update().where(self.Incident.id == INCIDENT_ID).values(**values))
            return
        values = self.event_values()
        if case.mode == "stored_event":
            allowed = {"payload", "event_type", "severity", "trust_score", "risk_score"}
            values.update({key: value for key, value in document.items() if key in allowed})
        db.execute(self.Event.__table__.insert().values(**values))
        if case.mode == "stored_raw":
            db.execute(
                self.Event.__table__.update().where(self.Event.id == EVENT_ID).values(
                    payload=case.raw.decode("utf-8", errors="replace")
                )
            )
        db.flush()

    def response(self, value: Any) -> bytes:
        return self.JSONResponse(value).body

    def session_response(self, db) -> bytes:
        values = self.incidents.replay_session(SESSION, principal=self.user_principal, db=db)
        models = self.list_adapter.validate_python(values)
        return self.response(self.list_adapter.dump_python(models, mode="json"))

    def close(self) -> None:
        self.engine.dispose()


@contextlib.contextmanager
def case_alarm(seconds: float):
    def timeout(signum, frame):
        del signum, frame
        raise CaseTimeout("per-case wall deadline exceeded")

    previous = signal.signal(signal.SIGALRM, timeout)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def record_failure(stats: Stats, stage: str, exc: Exception, case: Case, artifacts: Path) -> None:
    category = type(exc).__name__
    if category == "ValidationError":
        try:
            category += ":" + exc.errors(include_url=False)[0]["type"]
        except (AttributeError, IndexError, KeyError):
            pass
    signature = f"{stage}/{category}"
    stats.failures[signature] += 1
    if signature in stats.first_failure:
        return
    detail = {"case": case.label, "family": case.family, "detail": safe_detail(exc)}
    if len(stats.first_failure) < 32:
        filename = f"finding-{len(stats.first_failure) + 1:02d}.json"
        reproduction = {
            "mode": case.mode,
            "family": case.family,
            "label": case.label,
            "raw_hex_prefix": case.raw[:65_536].hex(),
            "raw_truncated": len(case.raw) > 65_536,
            "stage": stage,
            "exception": type(exc).__name__,
            "traceback": redact(traceback.format_exc(limit=8))[:8_192],
        }
        (artifacts / filename).write_text(json.dumps(reproduction, indent=2), encoding="utf-8")
        detail["artifact"] = filename
    stats.first_failure[signature] = detail


def observe(stats: Stats, stage: str, body: bytes | str) -> None:
    if has_canary(body):
        stats.secrets[stage] += 1


def execute_case(runtime: Runtime, guards: Guards, stats: Stats, case: Case, args, artifacts: Path) -> None:
    stats.attempted += 1
    stats.families[case.family] += 1
    stats.max_bytes = max(stats.max_bytes, len(case.raw))
    started = time.monotonic()
    stage = "harness_preflight"
    db = None
    try:
        db = runtime.Session(runtime.engine, autoflush=False, expire_on_commit=False)
        guards.active = True
        with case_alarm(args.case_seconds):
            if len(case.raw) > args.max_bytes:
                raise HarnessLimit("raw candidate exceeds harness byte cap")
            depth = nesting_depth(case.raw)
            stats.max_depth = max(stats.max_depth, depth)
            if depth > args.max_depth:
                raise HarnessLimit("raw candidate exceeds harness depth cap")
            if case.family == "duplicate-keys":
                try:
                    stats.duplicate_keys += duplicate_count(case.raw)
                except (ValueError, RecursionError, UnicodeDecodeError):
                    pass
            document = None
            if case.mode != "stored_raw":
                stage = "json_parse"
                try:
                    document = json.loads(case.raw)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    stats.outcomes["malformed_json_rejected"] += 1
                    return
                except RecursionError as exc:
                    guards.active = False
                    record_failure(stats, stage, exc, case, artifacts)
                    guards.active = True
                    stats.outcomes["json_recursion_error"] += 1
                    return
                stage = "harness_preflight"
                bound_nodes(document, args.max_nodes)
            if case.mode == "capture":
                stage = "capture_validation"
                try:
                    payload = runtime.Create.model_validate(document)
                except runtime.ValidationError as exc:
                    stats.outcomes["schema_rejected"] += 1
                    guards.active = False
                    try:
                        observe(
                            stats,
                            "validation_error_response",
                            runtime.response({"detail": runtime.jsonable_encoder(exc.errors(include_url=False))}),
                        )
                    finally:
                        guards.active = True
                    return
                stage = "capture_storage"
                event = runtime.telemetry.create_event(payload, principal=runtime.agent_principal, db=db)
                observe(stats, "capture_stored", encode(event.payload))
                stage = "capture_response"
                observe(stats, stage, runtime.response(runtime.Read.model_validate(event).model_dump(mode="json")))
            else:
                stage = "legacy_fixture_storage"
                if case.mode != "stored_raw" and not isinstance(document, dict):
                    raise HarnessLimit("legacy mutation is not an object")
                runtime.stored_case(case, document, db)
            stats.outcomes["capture_or_legacy_storage_ok"] += 1
            for replay_stage, call in (
                (
                    "replay_incident",
                    lambda: runtime.response(runtime.incidents.replay_incident(
                        INCIDENT_ID, principal=runtime.user_principal, db=db
                    )),
                ),
                ("replay_session", lambda: runtime.session_response(db)),
            ):
                stage = replay_stage
                guards.replaying = True
                try:
                    observe(stats, replay_stage, call())
                    stats.outcomes[f"{replay_stage}_ok"] += 1
                except SafetyViolation:
                    raise
                except Exception as exc:  # noqa: BLE001 - target failures must become findings
                    guards.active = False
                    record_failure(stats, replay_stage, exc, case, artifacts)
                    guards.active = True
                finally:
                    guards.replaying = False
    except HarnessLimit:
        stats.outcomes["harness_limit_rejected"] += 1
    except SafetyViolation:
        raise
    except Exception as exc:  # noqa: BLE001 - malformed input must not abort the campaign
        guards.active = False
        record_failure(stats, stage, exc, case, artifacts)
    finally:
        guards.active = guards.replaying = False
        if db is not None:
            db.rollback()
            db.close()
        stats.completed += 1
        stats.max_case_ms = max(stats.max_case_ms, (time.monotonic() - started) * 1000)


def control_probes(runtime: Runtime, guards: Guards, stats: Stats) -> None:
    """Check tenancy, rollback, SDK serialization, and read-only replay."""
    from fastapi import HTTPException
    from sqlalchemy import func, select

    try:
        from agent_sentinel import AgentSentinelClient

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                del args
                return False

            def read(self):
                return b"{}"

        wire: list[bytes] = []

        def no_http(request, **kwargs):
            del kwargs
            wire.append(request.data or b"")
            return FakeResponse()

        with patch("agent_sentinel.client.urllib.request.urlopen", no_http):
            client = AgentSentinelClient(
                "https://example.invalid", str(AGENT_ID), api_key="synthetic-header"
            )
            client.record_event(
                "audit.sdk", payload={"api_key": CANARIES[0], "token": CANARIES[1]}
            )
        observe(stats, "sdk_wire", wire[0])
        stats.controls["sdk_serialization_preserves_synthetic_secrets"] = has_canary(wire[0])
    except (ImportError, ModuleNotFoundError) as exc:
        stats.controls["sdk_probe"] = f"unavailable: {safe_detail(exc)}"

    with runtime.Session(runtime.engine, autoflush=False) as db:
        try:
            runtime.incidents.replay_incident(
                INCIDENT_ID, principal=runtime.other_principal, db=db
            )
        except HTTPException as exc:
            stats.controls["cross_tenant_incident_status"] = exc.status_code
        else:
            raise SafetyViolation("cross-tenant incident replay unexpectedly succeeded")
        count = db.scalar(select(func.count()).select_from(runtime.Event))
        if count != 0:
            raise SafetyViolation("a fuzz case escaped transaction rollback")
        stats.controls["rollback_leftover_telemetry_rows"] = count
        effect_payload = capture_document({
            "tool_name": "shell.execute",
            "arguments": {
                "command": "touch /tmp/omnirush/trace-robustness-MUST-NOT-EXIST",
                "url": "https://example.invalid/never-contact",
            },
        })["payload"]
        values = []
        for index in range(128):
            row = runtime.event_values(uuid.UUID(int=100 + index))
            if index == 0:
                row["payload"] = effect_payload
            values.append(row)
        db.execute(runtime.Event.__table__.insert(), values)
        guards.replaying = True
        try:
            replay_body = runtime.session_response(db)
            observe(stats, "effect_replay_output", replay_body)
            stats.controls["replay_returns_effect_arguments_as_data"] = (
                b"trace-robustness-MUST-NOT-EXIST" in replay_body
                and b"example.invalid" in replay_body
            )
            timeline = runtime.incidents.replay_incident(
                INCIDENT_ID, principal=runtime.user_principal, db=db
            )["timeline"]
            session = runtime.incidents.replay_session(
                SESSION, principal=runtime.user_principal, db=db
            )
            other = runtime.incidents.replay_session(
                SESSION, principal=runtime.other_principal, db=db
            )
            stats.controls.update({
                "bounded_population_rows": 128,
                "incident_rows_returned": len(timeline),
                "session_rows_returned": len(session),
                "other_tenant_session_rows": len(other),
            })
            if other:
                raise SafetyViolation("cross-tenant session replay exposed rows")
        finally:
            guards.replaying = False
            db.rollback()


def stdlib_preflight(cases, stats: Stats, args) -> None:
    """Exercise every mutation family when target dependencies are unavailable."""
    for case in cases:
        stats.attempted += 1
        stats.families[case.family] += 1
        stats.max_bytes = max(stats.max_bytes, len(case.raw))
        depth = nesting_depth(case.raw)
        stats.max_depth = max(stats.max_depth, depth)
        try:
            if len(case.raw) > args.max_bytes or depth > args.max_depth:
                raise HarnessLimit("candidate exceeds preflight cap")
            if case.mode != "stored_raw":
                document = json.loads(case.raw)
                bound_nodes(document, args.max_nodes)
                if case.family == "duplicate-keys":
                    stats.duplicate_keys += duplicate_count(case.raw)
            stats.outcomes["stdlib_preflight_ok"] += 1
        except (json.JSONDecodeError, UnicodeDecodeError):
            stats.outcomes["malformed_json_rejected"] += 1
        except RecursionError:
            stats.outcomes["stdlib_recursion_error"] += 1
        except HarnessLimit:
            stats.outcomes["harness_limit_rejected"] += 1
        finally:
            stats.completed += 1


def positive_int(low: int, high: int):
    def convert(value: str) -> int:
        number = int(value)
        if not low <= number <= high:
            raise argparse.ArgumentTypeError(f"must be between {low} and {high}")
        return number

    return convert


def bounded_float(low: float, high: float):
    def convert(value: str) -> float:
        number = float(value)
        if not math.isfinite(number) or not low <= number <= high:
            raise argparse.ArgumentTypeError(f"must be finite and between {low} and {high}")
        return number

    return convert


def arguments(argv: list[str] | None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mutations", type=positive_int(1, 2000), default=2000)
    parser.add_argument("--seed", type=int, default=20261011)
    parser.add_argument("--memory-mb", type=positive_int(128, 1024), default=512)
    parser.add_argument("--cpu-seconds", type=bounded_float(1, 120), default=30.0)
    parser.add_argument("--wall-seconds", type=bounded_float(1, 180), default=60.0)
    parser.add_argument("--case-seconds", type=bounded_float(0.01, 2), default=0.25)
    parser.add_argument("--max-bytes", type=positive_int(1024, 1_048_576), default=1_048_576)
    parser.add_argument("--max-depth", type=positive_int(16, 1500), default=1500)
    parser.add_argument("--max-nodes", type=positive_int(64, 30_000), default=30_000)
    parser.add_argument("--reproduce", type=Path, help="saved finding below /tmp/omnirush")
    parser.add_argument("--fail-on-findings", action="store_true")
    return parser.parse_args(argv)


def apply_limits(args) -> None:
    memory = args.memory_mb * 1024 * 1024
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    if hard != resource.RLIM_INFINITY:
        memory = min(memory, hard)
    if soft != resource.RLIM_INFINITY:
        memory = min(memory, soft)
    resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
    cpu = math.ceil(time.process_time() + args.cpu_seconds + 3)
    soft, hard = resource.getrlimit(resource.RLIMIT_CPU)
    if hard != resource.RLIM_INFINITY:
        cpu = min(cpu, hard)
    if soft != resource.RLIM_INFINITY:
        cpu = min(cpu, soft)
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def dependency_versions() -> str:
    names = ("fastapi", "pydantic", "sqlalchemy", "starlette")
    values = []
    for name in names:
        try:
            version = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            version = "missing"
        values.append(f"{name}={version}")
    return ", ".join(values)


def print_summary(stats: Stats, args, artifacts: Path, wall: float, cpu: float, status: str) -> None:
    print("Agentyc trace-robustness audit — 2026-10-11")
    print(f"status: {status}")
    print(f"python: {sys.version.split()[0]}")
    print(f"dependencies: {dependency_versions()}")
    print(f"source_sha256: {hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}")
    print(f"seed: {args.seed}")
    print(f"cases_requested: {1 if args.reproduce else args.mutations}")
    print(f"cases_attempted: {stats.attempted}")
    print(f"cases_completed: {stats.completed}")
    print(f"limits: memory={args.memory_mb}MiB cpu={args.cpu_seconds:g}s wall={args.wall_seconds:g}s per_case={args.case_seconds:g}s")
    print(f"input_caps: bytes={args.max_bytes} depth={args.max_depth} nodes={args.max_nodes}")
    print(f"usage: wall={wall:.3f}s cpu={cpu:.3f}s peak_rss={resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}KiB")
    print(f"observed: max_bytes={stats.max_bytes} max_depth={stats.max_depth} max_case={stats.max_case_ms:.3f}ms duplicate_keys={stats.duplicate_keys}")
    for heading, values in (
        ("outcomes", stats.outcomes),
        ("families", stats.families),
        ("synthetic_secret_disclosures", stats.secrets),
        ("controls", stats.controls),
    ):
        print(f"{heading}:")
        for key, value in sorted(values.items()):
            print(f"  {key}: {value}")
    print("target_failures (caught exceptions/HTTP-500 candidates, not process exits):")
    for signature, count in sorted(stats.failures.items()):
        first = stats.first_failure[signature]
        print(f"  {signature}: {count}; first={first['case']}; artifact={first.get('artifact', 'cap reached')}")
        print(f"    {first['detail']}")
    print(f"artifacts: {artifacts}")
    print("network_targets: none (SDK urlopen stub; socket/DNS/process traps installed)")
    if stats.controls.get("target_runtime_executed"):
        print("database: fresh sqlite:// in-memory, rollback-only case sessions")
    else:
        print("database: target runtime unavailable; standard-library preflight only")
    print("application_startup_workers_live_tools: not invoked")
    print("notes: corpus seeds are included in the case budget; legacy cases model corrupt/older SQL rows")


def load_runtime(guards: Guards) -> tuple[Runtime | None, str | None]:
    try:
        return Runtime(guards), None
    except (ImportError, ModuleNotFoundError) as exc:
        return None, f"{type(exc).__name__}: {safe_detail(exc)}"


def main(argv: list[str] | None = None) -> int:
    args = arguments(argv)
    apply_limits(args)
    configure_test_environment()
    guards = Guards()
    sys.addaudithook(guards.audit)
    guards.self_check()
    if not TMP_ROOT.is_dir():
        raise SafetyViolation("/tmp/omnirush must exist before running the harness")
    artifacts = Path(tempfile.mkdtemp(prefix="agentyc-trace-robustness-", dir=TMP_ROOT))
    stats = Stats()
    started_wall, started_cpu = time.monotonic(), time.process_time()
    runtime = None
    status = "complete"
    try:
        runtime, runtime_error = load_runtime(guards)
        seeds = corpus()
        if args.reproduce:
            path = args.reproduce.resolve()
            if not path.is_relative_to(TMP_ROOT.resolve()) or path.stat().st_size > 3 * args.max_bytes:
                raise SafetyViolation("reproduction must be bounded and below /tmp/omnirush")
            saved = json.loads(path.read_text(encoding="utf-8"))
            if saved["mode"] not in {"capture", "stored_event", "stored_incident", "stored_raw"}:
                raise SafetyViolation("unknown reproduction mode")
            cases = [Case(saved["mode"], saved["family"], saved["label"], bytes.fromhex(saved["raw_hex_prefix"]))]
        else:
            rng = random.Random(args.seed)
            cases = (seeds[index] if index < len(seeds) else mutation(rng, index, seeds) for index in range(args.mutations))
        if runtime is None:
            stats.controls["target_runtime_executed"] = False
            stats.controls["runtime_unavailable"] = runtime_error or "unknown import failure"
            stdlib_preflight(cases, stats, args)
            status = "runtime_unavailable"
        else:
            stats.controls["target_runtime_executed"] = True
            for case in cases:
                if time.process_time() - started_cpu >= args.cpu_seconds or time.monotonic() - started_wall >= args.wall_seconds:
                    status = "budget_exhausted"
                    break
                execute_case(runtime, guards, stats, case, args, artifacts)
            with case_alarm(min(2.0, args.case_seconds * 8)):
                control_probes(runtime, guards, stats)
            stats.controls["global_settings_database"] = "sqlite://"
        stats.controls.update({
            f"blocked_{key}_attempts": guards.attempts[key]
            for key in ("network", "process", "file_io", "replay_write")
        })
        stats.controls["guard_self_check"] = "passed"
    except Exception as exc:  # noqa: BLE001 - preserve a bounded harness summary
        status = "harness_failed"
        stats.controls["harness_error"] = safe_detail(f"{type(exc).__name__}: {exc}")
    finally:
        guards.active = guards.replaying = False
        if runtime is not None:
            runtime.close()
    print_summary(stats, args, artifacts, time.monotonic() - started_wall, time.process_time() - started_cpu, status)
    if status != "complete" or guards.attempts:
        return 2
    return int(args.fail_on_findings and bool(stats.failures or stats.secrets))


if __name__ == "__main__":
    raise SystemExit(main())
