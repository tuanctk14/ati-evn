"""Bot 2 — Analyst Command Bot. Standalone process."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from aiogram import Bot, Dispatcher, Router
from aiogram.types import BotCommand, Message
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from ati_evn.agent.session.cleanup import cleanup_expired_sessions
from ati_evn.campaigns.detector import run_detection_once as campaign_detect
from ati_evn.config import get_settings
from ati_evn.external.grayhat_weekly import run_weekly_grayhat_scan
from ati_evn.external.weekly_scan import run_weekly_censys_scan
from ati_evn.fetchers.scheduler import register_feed_jobs, startup_catchup
from ati_evn.ingestion.cleanup import cleanup_expired_ingestions
from ati_evn.telegram.auth import AllowlistMiddleware
from ati_evn.telegram.commands.action import router as action_router
from ati_evn.telegram.commands.add_asset import router as add_asset_router
from ati_evn.telegram.commands.add_test_campaign import router as add_test_campaign_router
from ati_evn.telegram.commands.add_customer import router as add_customer_router
from ati_evn.telegram.commands.add_ioc import router as add_ioc_router
from ati_evn.telegram.commands.campaign_action import router as campaign_action_router
from ati_evn.telegram.commands.campaign_query import router as campaign_query_router
from ati_evn.telegram.commands.confirm_ingest import router as confirm_ingest_router
from ati_evn.telegram.commands.delete_asset import router as delete_asset_router
from ati_evn.telegram.commands.edit_ingest import router as edit_ingest_router
from ati_evn.telegram.commands.ingest import router as ingest_router
from ati_evn.telegram.commands.list_ingests import router as list_ingests_router
from ati_evn.telegram.commands.force_fetch import router as force_fetch_router
from ati_evn.telegram.commands.reject_ingest import router as reject_ingest_router
from ati_evn.telegram.commands.scan_censys import router as scan_censys_router
from ati_evn.telegram.commands.scan_ghwarfare import router as scan_ghwarfare_router
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

COMMAND_MENU = [
    BotCommand(command="start", description="Bắt đầu và menu chính"),
    BotCommand(command="help", description="Hướng dẫn sử dụng"),
    BotCommand(command="finding", description="Xem chi tiết Finding"),
    BotCommand(command="cve", description="Chi tiết CVE và ATT&CK context"),
    BotCommand(command="ioc", description="Chi tiết IOC (IP/domain/hash)"),
    BotCommand(command="customer", description="Chi tiết customer/subsidiary"),
    BotCommand(command="asset", description="Chi tiết tài sản"),
    BotCommand(command="list_open", description="Danh sách Finding đang mở"),
    BotCommand(command="list_alerts", description="Danh sách alert gần đây"),
    BotCommand(command="stats", description="Dashboard tổng quan"),
    BotCommand(command="rule", description="Sinh Sigma rule cho CVE"),
    BotCommand(command="playbook", description="Tạo playbook NIST 800-61"),
    BotCommand(command="export", description="Xuất báo cáo tuần/tháng"),
    BotCommand(command="rescan", description="Chạy lại matcher"),
    BotCommand(command="list_campaigns", description="Danh sách Campaign Candidate"),
    BotCommand(command="ingest", description="Nhập bài báo/report để enrich"),
    BotCommand(command="list_ingests", description="Danh sách phiên nhập bài báo"),
    BotCommand(command="scan_censys", description="Quét external service qua Censys"),
    BotCommand(command="scan_ghwarfare", description="Kiểm tra lộ lọt tài liệu"),
]


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

    try:
        await bot.set_my_commands(COMMAND_MENU)
        logger.info("Telegram command menu registered: %d commands", len(COMMAND_MENU))
    except Exception as e:
        logger.warning("Failed to register command menu: %s", e)

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
    dp.include_router(add_test_campaign_router)
    dp.include_router(campaign_query_router)
    dp.include_router(campaign_action_router)
    dp.include_router(ingest_router)
    dp.include_router(confirm_ingest_router)
    dp.include_router(reject_ingest_router)
    dp.include_router(edit_ingest_router)
    dp.include_router(list_ingests_router)
    dp.include_router(scan_censys_router)
    dp.include_router(scan_ghwarfare_router)
    dp.include_router(force_fetch_router)

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
    scheduler.add_job(
        campaign_detect,
        "interval",
        hours=1,
        id="campaign_detection",
        # First run 5 min after boot to not delay startup
        next_run_time=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    scheduler.add_job(
        cleanup_expired_ingestions,
        "interval",
        minutes=15,
        id="ingestion_cleanup",
    )
    scheduler.add_job(
        run_weekly_censys_scan,
        "cron",
        day_of_week="mon",
        hour=2,
        minute=0,
        id="weekly_censys_scan",
    )
    scheduler.add_job(
        run_weekly_grayhat_scan,
        "cron",
        day_of_week="sun",
        hour=4,
        minute=0,
        id="weekly_grayhat_scan",
    )
    fetcher_job_count = register_feed_jobs(scheduler)
    scheduler.start()
    logger.info("Session cleanup scheduled (every 5min)")
    logger.info("Campaign detection scheduled (hourly)")
    logger.info("Ingestion cleanup scheduled (15min)")
    logger.info("Weekly Censys scan scheduled (Monday 02:00 UTC)")
    logger.info("Weekly GrayHatWarfare scan scheduled (Sunday 04:00 UTC)")
    logger.info("Fetcher scheduler: %d feed jobs registered", fetcher_job_count)

    # Startup catch-up runs as a background task — fetchers can take
    # 10-30s each, and bot_analyst must not delay Telegram polling start
    # while waiting on them.
    asyncio.create_task(startup_catchup())

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
