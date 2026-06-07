from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sdk", "python")))

from agent_sentinel import AgentSentinelClient, SecurityBlock


BASE_URL = os.getenv("AGENT_SENTINEL_URL", "http://localhost:8000")
AGENT_ID = os.getenv("AGENT_SENTINEL_AGENT_ID", "replace-with-agent-id")
API_KEY = os.getenv("AGENT_SENTINEL_API_KEY")


def main() -> None:
    if AGENT_ID == "replace-with-agent-id":
        print("Set AGENT_SENTINEL_AGENT_ID to a registered agent id first.")
        return

    sentinel = AgentSentinelClient(BASE_URL, AGENT_ID, API_KEY, fail_closed=True)
    session_id = "demo-sales-attack-live"
    goal = "Summarize quarterly sales trends"

    sentinel.record_event("prompt.received", session_id=session_id, payload={"goal": goal}, trust_score=75, risk_score=15)

    try:
        sentinel.before_tool_call(
            session_id=session_id,
            goal=goal,
            tool_name="hr_database",
            tool_type="database",
            action="read",
            resource="payroll_records",
            resource_sensitivity="restricted",
            reasoning_summary="Need more context, attempting to inspect employee payroll records.",
        )
        print("Unexpected allow: check policy configuration.")
    except SecurityBlock as exc:
        print("Blocked as expected")
        print(exc.decision)


if __name__ == "__main__":
    main()
