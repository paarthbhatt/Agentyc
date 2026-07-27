from __future__ import annotations

import unittest
from unittest.mock import Mock

from agent_sentinel import SecurityBlock, SentinelNodeWrapper


class SentinelNodeWrapperTests(unittest.TestCase):
    def test_successful_node_is_enforced_and_logged(self) -> None:
        client = Mock()

        @SentinelNodeWrapper(client, "summarize")
        def node(state: dict) -> dict:
            return {"summary": state["text"].upper()}

        result = node({"text": "hello"})

        self.assertEqual(result, {"summary": "HELLO"})
        client.before_tool_call.assert_called_once()
        client.record_event.assert_called_once_with(
            "langgraph.state.transition",
            severity="info",
            payload={"node": "summarize", "state_update": result},
        )

    def test_blocked_node_is_not_executed_and_is_logged(self) -> None:
        client = Mock()
        client.before_tool_call.side_effect = SecurityBlock(
            {"decision": "block", "reasons": ["policy denied"]}
        )
        node = Mock(return_value={"should": "not run"})
        wrapped = SentinelNodeWrapper(client, "restricted")(node)
        state = {"request": "payroll"}

        with self.assertRaisesRegex(RuntimeError, "blocked execution"):
            wrapped(state)

        node.assert_not_called()
        client.record_event.assert_called_once()
        event_type, = client.record_event.call_args.args
        self.assertEqual(event_type, "langgraph.node.blocked")
        self.assertEqual(client.record_event.call_args.kwargs["severity"], "critical")
        self.assertEqual(client.record_event.call_args.kwargs["payload"]["state"], state)

    def test_node_error_is_logged_and_reraised(self) -> None:
        client = Mock()
        failure = ValueError("bad state")

        @SentinelNodeWrapper(client, "broken")
        def node(state: dict) -> dict:
            raise failure

        with self.assertRaises(ValueError) as raised:
            node({})

        self.assertIs(raised.exception, failure)
        client.record_event.assert_called_once_with(
            "langgraph.node.error",
            severity="high",
            payload={"node": "broken", "error": "bad state"},
        )


if __name__ == "__main__":
    unittest.main()
