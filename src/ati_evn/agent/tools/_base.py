"""Tool registration primitives."""
from __future__ import annotations

import functools
import logging
from dataclasses import dataclass
from typing import Awaitable, Callable

logger = logging.getLogger("ati_evn.agent.tools")

TOOL_REGISTRY: dict[str, "Tool"] = {}


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict  # JSON schema
    handler: Callable[..., Awaitable[dict]]


def register_tool(
    name: str,
    description: str,
    parameters: dict,
    *,
    accepts_session_id: bool = False,
) -> Callable:
    """Decorator to register an async function as a tool.

    accepts_session_id: set True only by register_action_tool -- its
    wrapper expects a _session_id kwarg (used for the pending-confirmation
    registry) and pops it before delegating to the underlying tool fn.
    Plain query tools never see it.
    """
    def decorator(fn):
        @functools.wraps(fn)
        async def wrapper(**kwargs) -> dict:
            if not accepts_session_id:
                kwargs.pop("_session_id", None)
            try:
                result = await fn(**kwargs)
                if not isinstance(result, dict):
                    raise TypeError(
                        f"Tool {name} must return dict, got {type(result)}"
                    )
                if "success" not in result:
                    result = {"success": True, **result}
                return result
            except Exception as e:
                logger.exception("Tool %s error: %s", name, e)
                return tool_error(str(e))
        TOOL_REGISTRY[name] = Tool(
            name=name, description=description,
            parameters=parameters, handler=wrapper,
        )
        return wrapper
    return decorator


def tool_error(msg: str, *, hint: str | None = None) -> dict:
    """Standard error envelope for tools."""
    return {
        "success": False,
        "error": msg[:500],
        "hint": hint or "",
    }


def get_all_openai_schemas() -> list[dict]:
    """Return list in OpenAI function-calling format."""
    return [
        {
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description,
                "parameters": t.parameters,
            },
        }
        for t in TOOL_REGISTRY.values()
    ]
