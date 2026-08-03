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

# In-process pending-confirmation registry: {(session_id, tool_name, args_hash):
# (expires_at, original_kwargs)}. Enforces the confirm-before-execute contract
# at the code layer instead of trusting the LLM to only send confirmed=True
# after a real user confirmation. original_kwargs is replayed verbatim on
# confirm (see wrapper below) rather than trusting whatever args the model
# resends -- models frequently drop optional/default args (e.g. window=7d)
# when the analyst confirms tersely ("OK"), which would otherwise hash-miss
# and reject a perfectly legitimate confirmation.
_pending_confirmations: dict[tuple[str, str, str], tuple[float, dict]] = {}


def _args_hash(kwargs: dict) -> str:
    """Stable hash of tool args, excluding the confirmed flag itself."""
    relevant = {k: v for k, v in kwargs.items() if k != "confirmed"}
    blob = json.dumps(relevant, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _prune_expired() -> None:
    now = time.monotonic()
    expired = [k for k, (exp, _) in _pending_confirmations.items() if exp < now]
    for k in expired:
        del _pending_confirmations[k]


def _find_pending_for_tool(
    session_id: str, tool_name: str, current_kwargs: dict | None = None,
) -> list[tuple[tuple[str, str, str], dict]]:
    """Non-expired pending confirmations for this (session, tool),
    regardless of args_hash -- used as a fallback when the strict
    (session, tool, args_hash) key doesn't match on confirm (e.g. the
    model resent a slightly reworded `reason` for the SAME action).

    If more than one pending entry exists for this tool (allowed since
    an analyst request can name multiple destructive actions in one
    message, e.g. "close #255 and mark #256 false positive" -- each
    gets its own independent pending entry), narrow by any argument
    keys the model's confirm call actually included (excluding
    `confirmed`) that match a candidate's original args -- typically
    an id-like field (finding_id, ioc, customer_id, ...) the model
    still remembers correctly even when it reworded `reason`. Only
    fall through to "genuinely ambiguous" (returning all candidates)
    when no single candidate is the unique best match."""
    candidates = [
        (key, original_kwargs)
        for key, (_, original_kwargs) in _pending_confirmations.items()
        if key[0] == session_id and key[1] == tool_name
    ]
    if len(candidates) <= 1 or not current_kwargs:
        return candidates

    ident_keys = {k for k in current_kwargs if k != "confirmed"}
    scored = [
        (
            sum(1 for k in ident_keys if k in orig and orig[k] == current_kwargs[k]),
            key, orig,
        )
        for key, orig in candidates
    ]
    scored.sort(key=lambda x: -x[0])
    if scored[0][0] > 0 and (len(scored) == 1 or scored[0][0] > scored[1][0]):
        return [(scored[0][1], scored[0][2])]
    return candidates


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
        fn_wants_bot_context = "_bot" in inspect.signature(fn).parameters

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
            accepts_session_id=True, accepts_bot_context=True,
        )
        @functools.wraps(fn)
        async def wrapper(**kwargs):
            session_id = str(kwargs.pop("_session_id", None) or "unknown")
            bot_ctx = kwargs.pop("_bot", None)
            chat_id_ctx = kwargs.pop("_chat_id", None)
            input_args = dict(kwargs)
            _prune_expired()

            if destructive and kwargs.get("confirmed"):
                strict_key = (session_id, name, _args_hash(kwargs))
                if strict_key in _pending_confirmations:
                    del _pending_confirmations[strict_key]
                else:
                    # Strict hash miss -- fall back to any pending
                    # confirmation for this (session, tool). If exactly
                    # one exists, replay ITS original args (not the
                    # model's possibly-incomplete re-call args) so a
                    # terse "OK"/"xac nhan" still executes the exact
                    # action the analyst was shown, never a different
                    # one.
                    candidates = _find_pending_for_tool(session_id, name, kwargs)
                    if len(candidates) == 1:
                        (matched_key, original_kwargs) = candidates[0]
                        del _pending_confirmations[matched_key]
                        recovered = dict(original_kwargs)
                        recovered["confirmed"] = True
                        logger.info(
                            "Action %s: confirm args didn't match pending hash -- "
                            "replaying original pending args instead", name,
                        )
                        kwargs = recovered
                        input_args = dict(kwargs)
                    elif len(candidates) > 1:
                        err = (
                            f"Multiple pending confirmations exist for {name} in "
                            "this session -- ambiguous which one to confirm. Ask "
                            "the analyst to restate the request from scratch."
                        )
                        await log_action(name, input_args, {"error": err}, "failed", err)
                        return tool_error(err)
                    else:
                        err = (
                            "confirmed=True was sent without a matching prior "
                            "PENDING_CONFIRMATION call in this session for this "
                            "tool -- call the tool first WITHOUT confirmed=True, "
                            "show the summary to the analyst, and only re-call "
                            "with confirmed=True after they explicitly confirm."
                        )
                        await log_action(name, input_args, {"error": err}, "failed", err)
                        return tool_error(err)

            extra_kwargs = {}
            if fn_wants_session_id:
                extra_kwargs["_session_id"] = session_id
            if fn_wants_bot_context:
                extra_kwargs["_bot"] = bot_ctx
                extra_kwargs["_chat_id"] = chat_id_ctx

            try:
                result = await fn(**kwargs, **extra_kwargs)
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
                    _pending_confirmations[key] = (
                        time.monotonic() + PENDING_TTL_SECONDS, dict(kwargs),
                    )
            elif isinstance(result, dict) and result.get("error"):
                status = "failed"

            await log_action(name, input_args, result, status)
            return result

        return wrapper
    return decorator
