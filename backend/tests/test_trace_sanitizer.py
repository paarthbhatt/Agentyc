from __future__ import annotations

import unittest

from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base, get_db
from app.main import app, settings
from app.schemas import TelemetryEventCreate
from app.services.trace_sanitizer import (
    MAX_DEPTH,
    MAX_ITEMS,
    MAX_NODES,
    MAX_STRING_LEN,
    REDACTED,
    PayloadBoundsError,
    sanitize_payload,
)

AGENT_ID = "00000000-0000-4000-8000-000000000001"


def _event(payload: dict) -> TelemetryEventCreate:
    return TelemetryEventCreate(agent_id=AGENT_ID, event_type="trace.audit", payload=payload)


class SecretRedactionTests(unittest.TestCase):
    def test_secret_named_keys_are_redacted(self) -> None:
        payload = {
            "api_key": "sk-abcdefghijklmnop",
            "password": "hunter2-very-secret",
            "token": "audit-token-value",
            "Authorization": "Bearer xyz.abc.def",
            "goal": "summarize sales",
        }
        clean = sanitize_payload(payload)
        self.assertEqual(clean["api_key"], REDACTED)
        self.assertEqual(clean["password"], REDACTED)
        self.assertEqual(clean["token"], REDACTED)
        self.assertEqual(clean["Authorization"], REDACTED)
        self.assertEqual(clean["goal"], "summarize sales")

    def test_nested_mappings_and_lists_are_redacted(self) -> None:
        payload = {
            "headers": {"authorization": "Bearer secret-token"},
            "nested": [{"password": "nested-secret"}, {"ok": "value"}],
        }
        clean = sanitize_payload(payload)
        self.assertEqual(clean["headers"]["authorization"], REDACTED)
        self.assertEqual(clean["nested"][0]["password"], REDACTED)
        self.assertEqual(clean["nested"][1]["ok"], "value")

    def test_credential_formats_in_free_text_are_scrubbed(self) -> None:
        payload = {
            "message": "connect with token=audit-token-20261011-abcdef and continue",
            "note": "use Bearer abc.def.ghi for auth",
            "cmd": "export API_KEY=«redacted:sk-…»",
        }
        clean = sanitize_payload(payload)
        self.assertNotIn("audit-token-20261011-abcdef", clean["message"])
        self.assertNotIn("abc.def.ghi", clean["note"])
        self.assertNotIn("«redacted:sk-…»", clean["cmd"])
        self.assertIn(REDACTED, clean["message"])

    def test_each_known_secret_shape_is_scrubbed(self) -> None:
        # One case per secret shape named in the work order (synthetic values).
        shapes = {
            "openai": "sk-abcd1234efgh5678ijkl",
            "github": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            "aws": "AKIAIOSFODNN7EXAMPLE",
            "privkey": "-----BEGIN RSA PRIVATE KEY-----\nMIIByz\n-----END RSA PRIVATE KEY-----",
        }
        for name, value in shapes.items():
            clean = sanitize_payload({"blob": f"prefix {value} suffix"})
            self.assertNotIn(value.splitlines()[0], clean["blob"], name)
            self.assertIn(REDACTED, clean["blob"], name)

    def test_sk_prefixed_key_in_plain_value_is_scrubbed(self) -> None:
        clean = sanitize_payload({"blob": "leading sk-ABCDEF1234567890 trailing"})
        self.assertNotIn("sk-ABCDEF1234567890", clean["blob"])

    def test_capture_schema_redacts_before_storage(self) -> None:
        event = _event({"api_key": "sk-shouldbegone", "goal": "ok"})
        self.assertEqual(event.payload["api_key"], REDACTED)
        self.assertEqual(event.payload["goal"], "ok")

    def test_non_mapping_payload_is_untouched_by_sanitizer(self) -> None:
        # Envelope schema rejects non-dict payloads; sanitizer must not raise.
        self.assertEqual(sanitize_payload("plain"), "plain")
        self.assertEqual(sanitize_payload([1, 2]), [1, 2])

    def test_unpaired_surrogate_is_scrubbed_to_be_encodable(self) -> None:
        # A lone UTF-16 surrogate cannot be UTF-8 encoded and would crash JSON
        # serialization on the capture/replay response (HTTP 500).
        clean = sanitize_payload({"note": "before\ud800after"})
        clean["note"].encode("utf-8")  # must not raise
        self.assertNotIn("\ud800", clean["note"])
        self.assertIn("before", clean["note"])
        self.assertIn("after", clean["note"])


class PayloadBoundsTests(unittest.TestCase):
    def test_depth_over_limit_is_rejected(self) -> None:
        node: dict = {"leaf": 1}
        for _ in range(MAX_DEPTH + 5):
            node = {"n": node}
        with self.assertRaises(PayloadBoundsError):
            sanitize_payload(node)

    def test_node_count_over_limit_is_rejected(self) -> None:
        # Many small containers inflate total node count beyond MAX_NODES.
        payload = {f"k{i}": {"v": i} for i in range(MAX_NODES)}
        with self.assertRaises(PayloadBoundsError):
            sanitize_payload(payload)

    def test_item_count_over_limit_is_rejected(self) -> None:
        with self.assertRaises(PayloadBoundsError):
            sanitize_payload({"items": [0] * (MAX_ITEMS + 1)})

    def test_string_length_over_limit_is_rejected(self) -> None:
        with self.assertRaises(PayloadBoundsError):
            sanitize_payload({"blob": "x" * (MAX_STRING_LEN + 1)})

    def test_within_bounds_payload_passes(self) -> None:
        payload = {"items": [0] * 10, "blob": "x" * 100, "nested": {"a": {"b": 1}}}
        self.assertEqual(sanitize_payload(payload)["items"], [0] * 10)

    def test_capture_schema_rejects_oversized_payload_as_validation_error(self) -> None:
        with self.assertRaises(ValidationError):
            _event({"blob": "x" * (MAX_STRING_LEN + 1)})

    def test_capture_schema_rejects_deep_payload_as_validation_error(self) -> None:
        node: dict = {"leaf": 1}
        for _ in range(MAX_DEPTH + 5):
            node = {"n": node}
        with self.assertRaises(ValidationError):
            _event(node)


class CaptureAndReplayEndToEndTests(unittest.TestCase):
    """Prove redaction and bounds hold across the real HTTP capture/replay path."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = create_engine(
            "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
        )
        cls.Session = sessionmaker(bind=cls.engine, autoflush=False, autocommit=False)
        Base.metadata.create_all(cls.engine)

        def override_db():
            db = cls.Session()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_db
        settings.rate_limit_enabled = False
        cls.client = TestClient(app)
        reg = cls.client.post(
            "/api/v1/auth/register",
            json={"email": "sanitize@example.com", "password": "strong-password-123", "org_name": "San"},
        )
        assert reg.status_code == 201, reg.text
        csrf = {"x-csrf-token": cls.client.cookies.get("sentinel_csrf")}
        agent = cls.client.post(
            "/api/v1/agents", headers=csrf, json={"name": "A", "role": "research_agent"}
        ).json()
        cls.agent_id = agent["agent"]["id"]
        cls.agent_headers = {"x-agent-sentinel-key": agent["api_key"]}

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(cls.engine)
        cls.engine.dispose()

    def _capture(self, payload: dict, session_id: str):
        return self.client.post(
            "/api/v1/telemetry/events",
            headers=self.agent_headers,
            json={
                "agent_id": self.agent_id,
                "session_id": session_id,
                "event_type": "trace.audit",
                "payload": payload,
            },
        )

    def test_secrets_are_redacted_before_storage_and_replay(self) -> None:
        secret = "audit-token-20261011-abcdef"
        resp = self._capture(
            {
                "api_key": secret,
                "headers": {"authorization": f"Bearer {secret}"},
                "message": f"token={secret}",
                "goal": "ok",
            },
            "replay-redaction",
        )
        self.assertEqual(resp.status_code, 201, resp.text)
        stored = resp.json()["payload"]
        self.assertEqual(stored["api_key"], REDACTED)
        self.assertEqual(stored["headers"]["authorization"], REDACTED)
        self.assertNotIn(secret, stored["message"])
        self.assertEqual(stored["goal"], "ok")

        replay = self.client.get("/api/v1/replay/sessions/replay-redaction")
        self.assertEqual(replay.status_code, 200, replay.text)
        self.assertNotIn(secret, replay.text)

    def test_oversized_payload_rejected_with_422_not_500(self) -> None:
        resp = self._capture({"blob": "x" * (MAX_STRING_LEN + 1)}, "bounds-size")
        self.assertEqual(resp.status_code, 422, resp.text)

    def test_deep_payload_rejected_with_422_not_500(self) -> None:
        node: dict = {"leaf": 1}
        for _ in range(MAX_DEPTH + 5):
            node = {"n": node}
        resp = self._capture(node, "bounds-depth")
        self.assertEqual(resp.status_code, 422, resp.text)

    def test_very_deep_payload_rejected_with_422_not_recursionerror_500(self) -> None:
        # A payload nested ~1000 deep used to overflow the recursion limit while
        # the 422 body serialized the echoed input, surfacing as HTTP 500. The
        # error body must now omit input and return a clean 422.
        node: dict = {"leaf": 1}
        for _ in range(1000):
            node = {"n": node}
        resp = self._capture(node, "bounds-very-deep")
        self.assertEqual(resp.status_code, 422, resp.text)
        self.assertNotIn("leaf", resp.text)

    def test_corrupt_non_dict_stored_payload_replays_without_500(self) -> None:
        from app.models import Agent, TelemetryEvent

        db = self.Session()
        try:
            agent = db.query(Agent).first()
            ev = TelemetryEvent(
                org_id=agent.org_id,
                agent_id=agent.id,
                session_id="corrupt-replay",
                event_type="trace.audit",
                severity="info",
                payload=None,  # legacy/corrupt row
            )
            db.add(ev)
            db.commit()
        finally:
            db.close()
        replay = self.client.get("/api/v1/replay/sessions/corrupt-replay")
        self.assertEqual(replay.status_code, 200, replay.text)
        self.assertEqual(replay.json()[0]["payload"], {})

    def test_corrupt_incident_evidence_and_actions_redact_secrets_on_replay(self) -> None:
        # A legacy/corrupt incident row can hold a non-dict evidence value or a
        # response_actions value of the wrong shape that embeds a secret. Replay
        # must coerce it cleanly (no HTTP 500) and never return the secret.
        from app.models import Agent, Incident

        secret = "sk-incident-leak-20261011-zzz"
        db = self.Session()
        try:
            agent = db.query(Agent).first()
            inc = Incident(
                org_id=agent.org_id,
                agent_id=agent.id,
                session_id="corrupt-incident",
                title="legacy",
                category="audit",
                severity="info",
                root_cause="legacy",
            )
            # Bypass response-model coercion by writing raw corrupt JSON shapes.
            inc.evidence = {"api_key": secret, "nested": {"token": secret}}
            inc.response_actions = {"token": secret}  # wrong type on purpose
            db.add(inc)
            db.commit()
            incident_id = str(inc.id)
        finally:
            db.close()
        replay = self.client.get(f"/api/v1/replay/incidents/{incident_id}")
        self.assertEqual(replay.status_code, 200, replay.text)
        self.assertNotIn(secret, replay.text)
        body = replay.json()["incident"]
        self.assertEqual(body["evidence"]["api_key"], REDACTED)
        self.assertEqual(body["evidence"]["nested"]["token"], REDACTED)
        self.assertNotIn(secret, "".join(body["response_actions"]))

    def test_validation_error_body_does_not_leak_secret_input(self) -> None:
        secret = "leaked-secret-20261011-zzz"
        resp = self.client.post(
            "/api/v1/telemetry/events",
            headers=self.agent_headers,
            json={
                "agent_id": self.agent_id,
                "session_id": "err",
                "event_type": "trace.audit",
                "severity": secret,  # invalid literal -> 422, input echoed in error
                "payload": {"api_key": secret},
            },
        )
        self.assertEqual(resp.status_code, 422, resp.text)
        self.assertNotIn(secret, resp.text)


if __name__ == "__main__":
    unittest.main()
