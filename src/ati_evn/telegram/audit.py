"""Write to command_log table. Use as a decorator on command handlers.

Slice 16A: also mirrors priority commands' side effects into the
analyst's SessionState.command_log_recent, so the agent's free-text
loop can resolve temporal-anaphoric references ("CVE moi ingest") to
actions the analyst took via slash-command, not just via the agent
itself. See register_command_tool_call() -- a handler opts in by
calling it explicitly; handlers that never call it still get minimal
tracking (command name only, no tool_calls detail), which is the
expected/sufficient behavior for read-only commands per slice 16A's
priority list (T4).
"""
from __future__ import annotations

import functools
import logging
import time

from aiogram.types import Message

from ati_evn.agent.session.state import load_or_create, save
from ati_evn.db.models import CommandLog
from ati_evn.db.session import async_session

logger = logging.getLogger("ati_evn.telegram.audit")


def register_command_tool_call(
    message: Message, *, tool_name: str, output_summary: str,
    entity_ids: list | None = None,
) -> None:
    """Call from within a command handler, after a meaningful side
    effect (entity created/modified), to record it for session
    temporal-anaphora resolution. No-op if called outside a
    @log_command-wrapped handler (the attribute is simply unused)."""
    if not hasattr(message, "_command_tool_calls"):
        message._command_tool_calls = []
    message._command_tool_calls.append({
        "tool_name": tool_name,
        "output_summary": str(output_summary)[:300],
        "entity_ids": entity_ids or [],
    })


def log_command(command_name: str):
    """Decorator for command handlers. Wraps to record a command_log row
    and, since slice 16A, a SessionState.command_log_recent entry."""
    def decorator(handler):
        @functools.wraps(handler)
        async def wrapper(message: Message, *args, **kwargs):
            start = time.monotonic()
            status = "ok"
            summary: str | None = None
            error: str | None = None
            text = message.text or ""
            parts = text.split(maxsplit=1)
            args_summary = parts[1][:200] if len(parts) > 1 else ""
            try:
                result = await handler(message, *args, **kwargs)
                if isinstance(result, dict):
                    summary = result.get("summary")
                return result
            except Exception as e:
                status = "error"
                error = str(e)[:500]
                logger.exception("Command %s error: %s", command_name, e)
                try:
                    await message.answer(f"⚠️ Lỗi khi xử lý lệnh: {str(e)[:200]}")
                except Exception:
                    pass
                raise
            finally:
                elapsed_ms = int((time.monotonic() - start) * 1000)
                args_dict: dict = {}
                if len(parts) > 1:
                    args_dict["raw"] = parts[1][:500]
                try:
                    async with async_session() as session:
                        entry = CommandLog(
                            telegram_user_id=message.from_user.id,
                            telegram_username=message.from_user.username,
                            command=command_name,
                            args=args_dict,
                            result_status=status,
                            result_summary=summary,
                            error=error,
                            latency_ms=elapsed_ms,
                        )
                        session.add(entry)
                        await session.commit()
                except Exception as e:
                    logger.warning("Failed to write command_log: %s", e)

                try:
                    session_state = await load_or_create(message.from_user.id)
                    session_state.append_command_log(
                        command_name=command_name,
                        args_summary=args_summary,
                        tool_calls=getattr(message, "_command_tool_calls", []),
                    )
                    await save(session_state, is_command_log_update=True)
                except Exception as e:
                    logger.warning("Failed to write command_log_recent: %s", e)
        return wrapper
    return decorator
