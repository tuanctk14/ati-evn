"""Helpers for action tools -- confirmation flow + audit log.

Pattern:
  @register_action_tool(
      name="delete_ioc",
      destructive=True,
      description="Soft-delete IOC and its findings.",
      parameters={...},
  )
  async def delete_ioc(ioc: str, confirmed: bool = False, ...) -> dict:
      if not confirmed:
          return pending_confirmation({
              "action": "delete IOC",
              "target": ioc,
              "impact": "Also soft-deletes 3 linked findings",
          })
      ...
      return {"status": "deleted", ...}
"""
from __future__ import annotations

import functools
import hashlib
import inspect
import json
import logging
import time

from ati_evn.agent.tools._base import register_tool, tool_error
from ati_evn.db.models import AgentActionLog
from ati_evn.db.session import async_session

logger = logging.getLogger("ati_evn.agent.action_base")

PENDING_TTL_SECONDS = 300  # 5 minutes

# In-process pending-confirmation registry: {(session_id, tool_name, args_hash): expires_at}.
# Enforces the confirm-before-execute contract at the code layer instead of
# trusting the LLM to only send confirmed=True after a real user confirmation.
_pending_confirmations: dict[tuple[str, str, str], float] = {}


def _args_hash(kwargs: dict) -> str:
    """Stable hash of tool args, excluding the confirmed flag itself."""
    relevant = {k: v for k, v in kwargs.items() if k != "confirmed"}
    blob = json.dumps(relevant, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _prune_expired() -> None:
    now = time.monotonic()
    expired = [k for k, exp in _pending_confirmations.items() if exp < now]
    for k in expired:
        del _pending_confirmations[k]


def pending_confirmation(summary: dict) -> dict:
    """Return response indicating confirmation needed.

    Agent shows summary to analyst and re-calls with confirmed=True
    after analyst confirms.
    """
    return {
        "status": "PENDING_CONFIRMATION",
        "requires_confirmation": True,
        "summary": summary,
        "hint": "Trả lời 'xác nhận' hoặc 'yes' để thực hiện. Nếu muốn huỷ, nói rõ.",
    }


async def log_action(
    tool_name: str, input_args: dict, output_result: dict,
    status: str, error_message: str | None = None,
) -> None:
    """Persist action to agent_action_log."""
    safe_input = {k: v for k, v in input_args.items() if k not in ("session", "_internal_ctx")}
    safe_output = output_result
    if len(str(output_result)) > 4000:
        safe_output = {
            "_truncated": True,
            "status": output_result.get("status") if isinstance(output_result, dict) else None,
            "size": len(str(output_result)),
        }

    async with async_session() as session:
        log = AgentActionLog(
            tool_name=tool_name,
            input_args=safe_input,
            output_result=safe_output,
            status=status,
            error_message=error_message,
        )
        session.add(log)
        await session.commit()


def register_action_tool(
    name: str, description: str, parameters: dict,
    destructive: bool = True,
):
    """Decorator that combines register_tool + audit logging.

    destructive=True: adds "confirmed: bool" to parameters if not present,
    and every call (pending or executed) is persisted to agent_action_log.
    destructive=False: auto-execute, no confirmation param needed, but
    still logged (status='executed') for audit completeness.
    """
    def decorator(fn):
        fn_wants_session_id = "_session_id" in inspect.signature(fn).parameters

        if destructive:
            props = parameters.setdefault("properties", {})
            if "confirmed" not in props:
                props["confirmed"] = {
                    "type": "boolean",
                    "default": False,
                    "description": (
                        "Set true after analyst explicitly confirms. "
                        "First call returns PENDING_CONFIRMATION."
                    ),
                }

        desc = description
        if destructive:
            desc += (
                " [DESTRUCTIVE — first call returns PENDING_CONFIRMATION "
                "with impact summary. After analyst confirms, re-call "
                "with confirmed=True.]"
            )

        @register_tool(
            name=name, description=desc, parameters=parameters,
            accepts_session_id=True,
        )
        @functools.wraps(fn)
        async def wrapper(**kwargs):
            session_id = str(kwargs.pop("_session_id", None) or "unknown")
            input_args = dict(kwargs)
            _prune_expired()

            if destructive:
                key = (session_id, name, _args_hash(kwargs))
                if kwargs.get("confirmed"):
                    if key not in _pending_confirmations:
                        err = (
                            "confirmed=True was sent without a matching prior "
                            "PENDING_CONFIRMATION call in this session (same "
                            "tool + same args) -- call the tool first WITHOUT "
                            "confirmed=True, show the summary to the analyst, "
                            "and only re-call with confirmed=True after they "
                            "explicitly confirm."
                        )
                        await log_action(name, input_args, {"error": err}, "failed", err)
                        return tool_error(err)
                    del _pending_confirmations[key]

            try:
                if fn_wants_session_id:
                    result = await fn(**kwargs, _session_id=session_id)
                else:
                    result = await fn(**kwargs)
            except Exception as e:
                logger.exception("Action tool %s failed", name)
                err = f"{type(e).__name__}: {str(e)[:200]}"
                await log_action(name, input_args, {"error": err}, "failed", err)
                return tool_error(f"Tool execution failed: {err}")

            status = "executed"
            if isinstance(result, dict) and result.get("requires_confirmation"):
                status = "pending_confirmation"
                if destructive:
                    key = (session_id, name, _args_hash(kwargs))
                    _pending_confirmations[key] = time.monotonic() + PENDING_TTL_SECONDS
            elif isinstance(result, dict) and result.get("error"):
                status = "failed"

            await log_action(name, input_args, result, status)
            return result

        return wrapper
    return decorator
