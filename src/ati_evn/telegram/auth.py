"""Allowlist check for Bot 2. Reject if user_id not in
settings.allowed_user_ids_set."""
from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable

from aiogram import BaseMiddleware
from aiogram.types import Message, TelegramObject

from ati_evn.config import get_settings

logger = logging.getLogger("ati_evn.telegram.auth")


class AllowlistMiddleware(BaseMiddleware):
    async def __call__(
        self,
        handler: Callable[[TelegramObject, dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: dict[str, Any],
    ) -> Any:
        if not isinstance(event, Message):
            return await handler(event, data)
        user = event.from_user
        if not user:
            logger.warning("Message without user; rejecting")
            return
        allowlist = get_settings().allowed_user_ids_set
        if not allowlist:
            logger.error("TELEGRAM_ALLOWED_USER_IDS empty — rejecting ALL. "
                         "Set it in .env or bot is unusable.")
            await event.answer(
                "⛔ Bot chưa cấu hình allowlist. Liên hệ admin."
            )
            return
        if user.id not in allowlist:
            logger.warning("Rejected user_id=%d username=%s", user.id, user.username)
            await event.answer(
                f"⛔ User ID {user.id} không có quyền dùng bot này."
            )
            return
        return await handler(event, data)
