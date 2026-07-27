# Agent Sentinel Python SDK

The Agent Sentinel SDK records agent telemetry and checks actions against the
Agent Sentinel runtime policy boundary before execution.

```python
from agent_sentinel import AgentSentinelClient, SecurityBlock

client = AgentSentinelClient(
    base_url="http://localhost:8000",
    api_key="as_live_...",
    agent_id="00000000-0000-0000-0000-000000000000",
)

try:
    decision = client.before_tool_call(
        goal="Summarize quarterly sales",
        tool_name="sales_database",
        action="read",
        resource="quarterly_sales",
        action_id="workflow-step-42",
    )
except SecurityBlock as exc:
    print(f"Blocked: {exc}")
```

Clients fail closed on network errors by default. Set `fail_closed=False` only
for low-risk telemetry paths where availability is more important than runtime
enforcement.
