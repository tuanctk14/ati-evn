"""Write to command_log table. Use as a decorator on command handlers."""
from __future__ import annotations

import functools
import logging
import time

from aiogram.types import Message

from ati_evn.db.models import CommandLog
from ati_evn.db.session import async_session

logger = logging.getLogger("ati_evn.telegram.audit")


def log_command(command_name: str):
    """Decorator for command handlers. Wraps to record a command_log row."""
    def decorator(handler):
        @functools.wraps(handler)
        async def wrapper(message: Message, *args, **kwargs):
            start = time.monotonic()
            status = "ok"
            summary: str | None = None
            error: str | None = None
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
                text = message.text or ""
                parts = text.split(maxsplit=1)
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
        return wrapper
    return decorator
