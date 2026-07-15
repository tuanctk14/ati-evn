"""Bot 2 — Analyst Command Bot. Standalone process."""
from __future__ import annotations

import logging

from aiogram import Bot, Dispatcher, Router
from aiogram.types import Message
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from ati_evn.agent.session.cleanup import cleanup_expired_sessions
from ati_evn.config import get_settings
from ati_evn.telegram.auth import AllowlistMiddleware
from ati_evn.telegram.commands.action import router as action_router
from ati_evn.telegram.commands.add_asset import router as add_asset_router
from ati_evn.telegram.commands.add_customer import router as add_customer_router
from ati_evn.telegram.commands.add_ioc import router as add_ioc_router
from ati_evn.telegram.commands.delete_asset import router as delete_asset_router
from ati_evn.telegram.commands.delete_customer import router as delete_customer_router
from ati_evn.telegram.commands.delete_ioc import router as delete_ioc_router
from ati_evn.telegram.commands.export import router as export_router
from ati_evn.telegram.commands.help import router as help_router
from ati_evn.telegram.commands.playbook import router as playbook_router
from ati_evn.telegram.commands.query import router as query_router
from ati_evn.telegram.commands.rescan import router as rescan_router
from ati_evn.telegram.commands.restore_asset import router as restore_asset_router
from ati_evn.telegram.commands.restore_customer import router as restore_customer_router
from ati_evn.telegram.commands.restore_ioc import router as restore_ioc_router
from ati_evn.telegram.commands.rule import router as rule_router
from ati_evn.telegram.commands.update_asset import router as update_asset_router
from ati_evn.telegram.commands.update_customer import router as update_customer_router
from ati_evn.telegram.commands.update_ioc import router as update_ioc_router
from ati_evn.telegram.commands.agent_handler import handle_free_text

logger = logging.getLogger("ati_evn.bot_analyst")


async def run_forever() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )
    settings = get_settings()
    if not settings.telegram_analyst_bot_token:
        logger.error("TELEGRAM_ANALYST_BOT_TOKEN missing; exiting")
        return 2
    if not settings.allowed_user_ids_set:
        logger.error(
            "TELEGRAM_ALLOWED_USER_IDS empty — bot would reject all requests. "
            "Set it in .env."
        )
        return 2

    bot = Bot(token=settings.telegram_analyst_bot_token)
    dp = Dispatcher()
    dp.message.middleware(AllowlistMiddleware())
    dp.include_router(help_router)
    dp.include_router(query_router)
    dp.include_router(rule_router)
    dp.include_router(playbook_router)
    dp.include_router(export_router)
    dp.include_router(add_customer_router)
    dp.include_router(add_asset_router)
    dp.include_router(add_ioc_router)
    dp.include_router(update_customer_router)
    dp.include_router(update_asset_router)
    dp.include_router(update_ioc_router)
    dp.include_router(delete_customer_router)
    dp.include_router(delete_asset_router)
    dp.include_router(delete_ioc_router)
    dp.include_router(restore_customer_router)
    dp.include_router(restore_asset_router)
    dp.include_router(restore_ioc_router)
    dp.include_router(action_router)
    dp.include_router(rescan_router)

    # Catch-all for anything not matched by an explicit command router
    # above. MUST live in its own router included LAST — aiogram's
    # Router.propagate_event checks the current router's own observer
    # before descending into sub_routers, so a filterless handler
    # registered directly on `dp` would swallow every update before
    # help_router/query_router ever see it.
    #
    # `/unknown_command` -> rejection message. Free text -> agent loop
    # (function-calling -> ReAct fallback, see agent_handler.py).
    fallback_router = Router()

    @fallback_router.message()
    async def _catchall(message: Message):
        text = (message.text or "").strip()
        if not text:
            return
        if text.startswith("/"):
            cmd = text.split()[0]
            await message.answer(
                f"Lệnh {cmd} không tồn tại hoặc chưa được implement.\n"
                f"Gõ /help all để xem list."
            )
            return
        await handle_free_text(message)

    dp.include_router(fallback_router)

    # Session cleanup background task — agent_sessions rows past their
    # 30-min TTL (see agent/session/state.py) are swept every 5 minutes
    # so the table doesn't grow unbounded across long-running bot uptime.
    scheduler = AsyncIOScheduler()
    scheduler.add_job(
        cleanup_expired_sessions,
        "interval",
        minutes=5,
        id="agent_session_cleanup",
    )
    scheduler.start()
    logger.info("Session cleanup scheduled (every 5min)")

    logger.info(
        "Bot 2 (analyst) starting; allowlist=%s",
        settings.allowed_user_ids_set,
    )
    try:
        await dp.start_polling(bot)
    finally:
        scheduler.shutdown()
        await bot.session.close()
    return 0
