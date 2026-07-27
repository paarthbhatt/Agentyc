from __future__ import annotations

from io import BytesIO
import json
import unittest
import urllib.error
from unittest.mock import patch
import uuid

from agent_sentinel import AgentSentinelClient, AgentSentinelError, SecurityBlock


class StubResponse:
    def __init__(self, payload: dict | str):
        self.body = payload if isinstance(payload, str) else json.dumps(payload)

    def __enter__(self) -> "StubResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return self.body.encode("utf-8")


class AgentSentinelClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = AgentSentinelClient(
            "https://sentinel.example/",
            "agent-123",
            "secret-key",
        )

    @patch("agent_sentinel.client.urllib.request.urlopen")
    def test_record_event_sends_headers_and_idempotency_key(self, urlopen) -> None:
        urlopen.side_effect = [StubResponse({"id": "first"}), StubResponse({"id": "first"})]

        for _ in range(2):
            self.client.record_event("prompt.received", event_id="event-123")

        for request in (call.args[0] for call in urlopen.call_args_list):
            self.assertEqual(request.full_url, "https://sentinel.example/api/v1/telemetry/events")
            self.assertEqual(request.get_header("Content-type"), "application/json")
            self.assertEqual(request.get_header("X-agent-sentinel-key"), "secret-key")
            payload = json.loads(request.data)
            self.assertEqual(payload["client_event_id"], "event-123")
            self.assertEqual(payload["agent_id"], "agent-123")

    @patch("agent_sentinel.client.urllib.request.urlopen", return_value=StubResponse({"id": "event"}))
    def test_record_event_generates_client_event_id(self, urlopen) -> None:
        self.client.record_event("prompt.received")

        payload = json.loads(urlopen.call_args.args[0].data)
        uuid.UUID(payload["client_event_id"])

    @patch("agent_sentinel.client.urllib.request.urlopen", return_value=StubResponse({"id": "event"}))
    def test_log_event_is_a_compatible_alias(self, urlopen) -> None:
        self.client.log_event("legacy.event", client_event_id="legacy-1")

        payload = json.loads(urlopen.call_args.args[0].data)
        self.assertEqual(payload["event_type"], "legacy.event")
        self.assertEqual(payload["client_event_id"], "legacy-1")

    @patch("agent_sentinel.client.urllib.request.urlopen")
    def test_enforcement_action_ids_are_unique(self, urlopen) -> None:
        urlopen.side_effect = [
            StubResponse({"decision": "allow"}),
            StubResponse({"decision": "allow"}),
        ]

        for _ in range(2):
            self.client.before_tool_call(
                goal="Read a report",
                tool_name="reporting",
                action="read",
                resource="quarterly-report",
            )

        payloads = [
            json.loads(call.args[0].data)
            for call in urlopen.call_args_list
        ]
        self.assertNotEqual(payloads[0]["action_id"], payloads[1]["action_id"])
        self.assertTrue(payloads[0]["action_id"].startswith("sdk-"))

    @patch(
        "agent_sentinel.client.urllib.request.urlopen",
        return_value=StubResponse({"decision": "allow"}),
    )
    def test_enforcement_accepts_a_stable_action_id(self, urlopen) -> None:
        self.client.before_tool_call(
            goal="Retry a report read",
            tool_name="reporting",
            action="read",
            resource="quarterly-report",
            action_id="workflow-action-42",
        )

        payload = json.loads(urlopen.call_args.args[0].data)
        self.assertEqual(payload["action_id"], "workflow-action-42")

    @patch("agent_sentinel.client.urllib.request.urlopen")
    def test_network_failure_is_fail_closed_by_default(self, urlopen) -> None:
        urlopen.side_effect = urllib.error.URLError("offline")

        with self.assertRaises(SecurityBlock) as raised:
            self.client.before_tool_call(
                goal="test",
                tool_name="database",
                action="read",
                resource="records",
            )

        self.assertEqual(raised.exception.decision["decision"], "block")
        self.assertIn("offline", raised.exception.decision["reasons"][0])

    @patch("agent_sentinel.client.urllib.request.urlopen")
    def test_network_failure_can_fail_open(self, urlopen) -> None:
        urlopen.side_effect = urllib.error.URLError("offline")
        client = AgentSentinelClient("https://sentinel.example", "agent-123", fail_closed=False)

        decision = client.before_tool_call(
            goal="test",
            tool_name="database",
            action="read",
            resource="records",
        )

        self.assertEqual(decision["decision"], "log_only")

    @patch("agent_sentinel.client.urllib.request.urlopen")
    def test_http_errors_preserve_status_and_response_detail(self, urlopen) -> None:
        urlopen.side_effect = urllib.error.HTTPError(
            "https://sentinel.example/api/v1/telemetry/events",
            401,
            "Unauthorized",
            {},
            BytesIO(b'{"detail":"Invalid agent API key"}'),
        )

        with self.assertRaisesRegex(AgentSentinelError, "401.*Invalid agent API key"):
            self.client.record_event("prompt.received")

    def test_conflicting_event_ids_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "must match"):
            self.client.record_event(
                "prompt.received",
                event_id="event-a",
                client_event_id="event-b",
            )


if __name__ == "__main__":
    unittest.main()
