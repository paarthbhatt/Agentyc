import json
from functools import wraps
from typing import Any, Callable

from .client import AgentSentinelClient, SecurityBlock


def _record_node_event(
    client: AgentSentinelClient,
    event_type: str,
    *,
    severity: str,
    payload: dict[str, Any],
) -> None:
    client.record_event(event_type, severity=severity, payload=payload)


def SentinelNodeWrapper(
    client: AgentSentinelClient,
    node_name: str,
    goal: str = "Execute LangGraph Node",
    action: str = "execute_node",
    resource_sensitivity: str = "internal",
):
    """
    A wrapper for LangGraph node functions that enforces Agent Sentinel policies before execution
    and logs state transitions.
    """

    def decorator(node_func: Callable) -> Callable:
        @wraps(node_func)
        def wrapper(state: dict[str, Any], *args: Any, **kwargs: Any) -> Any:
            # 1. Enforce Policies before execution
            input_text = json.dumps(state, default=str)
            try:
                client.before_tool_call(
                    goal=goal,
                    tool_name=node_name,
                    action=action,
                    resource="langgraph_node",
                    resource_sensitivity=resource_sensitivity,
                    input_text=input_text,
                    metadata={"node_name": node_name, "state_keys": list(state.keys())},
                )
            except SecurityBlock as e:
                # If blocked, log the failure and raise
                _record_node_event(
                    client,
                    "langgraph.node.blocked",
                    severity="critical",
                    payload={"node": node_name, "reason": str(e), "state": state},
                )
                raise RuntimeError(f"Agent Sentinel blocked execution of node '{node_name}': {e}") from e

            # 2. Execute the original node function
            try:
                result = node_func(state, *args, **kwargs)
                
                # 3. Log the successful transition
                _record_node_event(
                    client,
                    "langgraph.state.transition",
                    severity="info",
                    payload={
                        "node": node_name,
                        "state_update": result,
                    },
                )
                return result
            except Exception as ex:
                _record_node_event(
                    client,
                    "langgraph.node.error",
                    severity="high",
                    payload={"node": node_name, "error": str(ex)},
                )
                raise

        return wrapper

    return decorator
