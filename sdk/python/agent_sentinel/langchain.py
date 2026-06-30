import json
from typing import Any, Callable

from .client import AgentSentinelClient, SecurityBlock


class SentinelLangchainTool:
    """A wrapper for LangChain tools that enforces Agent Sentinel policies before execution."""

    def __init__(
        self,
        tool: Any,
        client: AgentSentinelClient,
        goal: str = "Execute LangChain tool",
        action: str = "execute",
        resource: str = "tool_execution",
        resource_sensitivity: str = "internal",
    ):
        self.tool = tool
        self.client = client
        self.goal = goal
        self.action = action
        self.resource = resource
        self.resource_sensitivity = resource_sensitivity

        # Mirror LangChain tool properties
        self.name = getattr(tool, "name", tool.__class__.__name__)
        self.description = getattr(tool, "description", "")
        self.args_schema = getattr(tool, "args_schema", None)
        self.return_direct = getattr(tool, "return_direct", False)

    def _enforce(self, tool_input: Any) -> None:
        input_text = json.dumps(tool_input) if isinstance(tool_input, (dict, list)) else str(tool_input)
        try:
            self.client.before_tool_call(
                goal=self.goal,
                tool_name=self.name,
                action=self.action,
                resource=self.resource,
                resource_sensitivity=self.resource_sensitivity,
                input_text=input_text,
                metadata={"tool_description": self.description},
            )
        except SecurityBlock as e:
            # Re-raise as an error that the agent framework might catch, or just let it bubble up
            raise RuntimeError(f"Agent Sentinel blocked tool execution: {e}") from e

    def run(self, tool_input: Any, **kwargs: Any) -> Any:
        self._enforce(tool_input)
        if hasattr(self.tool, "run"):
            return self.tool.run(tool_input, **kwargs)
        return self.tool(tool_input, **kwargs)

    async def arun(self, tool_input: Any, **kwargs: Any) -> Any:
        # Note: the client is currently synchronous, so we run _enforce synchronously here.
        # In a fully async client, this would be await self.client.before_tool_call(...)
        self._enforce(tool_input)
        if hasattr(self.tool, "arun"):
            return await self.tool.arun(tool_input, **kwargs)
        # fallback to sync if no arun
        if hasattr(self.tool, "run"):
            return self.tool.run(tool_input, **kwargs)
        return self.tool(tool_input, **kwargs)


def with_sentinel(
    client: AgentSentinelClient,
    goal: str,
    action: str = "execute",
    resource: str = "function",
    resource_sensitivity: str = "internal",
):
    """Decorator to protect any Python function with Agent Sentinel before it executes."""

    def decorator(func: Callable) -> Callable:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            input_text = json.dumps({"args": args, "kwargs": kwargs}, default=str)
            try:
                client.before_tool_call(
                    goal=goal,
                    tool_name=func.__name__,
                    action=action,
                    resource=resource,
                    resource_sensitivity=resource_sensitivity,
                    input_text=input_text,
                    metadata={"tool_description": func.__doc__ or ""},
                )
            except SecurityBlock as e:
                raise RuntimeError(f"Agent Sentinel blocked function execution: {e}") from e

            return func(*args, **kwargs)

        return wrapper

    return decorator
