import json
from typing import Any, Callable, Dict
from functools import wraps

from .client import AgentSentinelClient, SecurityBlock

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
        def wrapper(state: Dict[str, Any], *args, **kwargs) -> Any:
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
                client.log_event(
                    event_type="langgraph.node.blocked",
                    severity="critical",
                    payload={"node": node_name, "reason": str(e), "state": state}
                )
                raise RuntimeError(f"Agent Sentinel blocked execution of node '{node_name}': {e}") from e

            # 2. Execute the original node function
            try:
                result = node_func(state, *args, **kwargs)
                
                # 3. Log the successful transition
                client.log_event(
                    event_type="langgraph.state.transition",
                    severity="info",
                    payload={
                        "node": node_name,
                        "state_update": result
                    }
                )
                return result
            except Exception as ex:
                client.log_event(
                    event_type="langgraph.node.error",
                    severity="high",
                    payload={"node": node_name, "error": str(ex)}
                )
                raise ex

        return wrapper

    return decorator
