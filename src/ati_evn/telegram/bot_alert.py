"""Bot 1 — Alert Notifier. Standalone process.

Loop:
  1. Every 5 seconds, poll alert_queue for pending items
  2. Group by customer_id
  3. For each customer, check batch trigger:
     - If >=3 pending in 60s window → batch dispatch
     - Else, dispatch individually
  4. For failed dispatches, set next_retry_at = now + 5min, attempt_count++
  5. Skip when attempt_count >= 5, mark state=failed

Retry worker uses the same loop — pending items with next_retry_at in past
are eligible.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from aiogram import Bot
from aiogram.exceptions import TelegramAPIError, TelegramRetryAfter
from sqlalchemy import or_, select

from ati_evn.alerts.batcher import check_and_batch
from ati_evn.config import get_settings
from ati_evn.db.models import AlertBatch, AlertQueue, Customer, Finding
from ati_evn.db.session import async_session
from ati_evn.telegram.formatter.alert import format_alert_batch, format_alert_single

logger = logging.getLogger("ati_evn.bot_alert")

POLL_INTERVAL_SECONDS = 5


async def _dispatch_single(bot: Bot, chat_id: str, alert: AlertQueue, session) -> bool:
    finding = await session.get(Finding, alert.finding_id)
    if not finding:
        logger.warning("Finding %d missing for alert %d", alert.finding_id, alert.id)
        return False
    customer = await session.get(Customer, alert.customer_id)
    customer_name = customer.name if customer else f"Customer#{alert.customer_id}"
    asset_display = finding.matched_asset or "-"
    message = format_alert_single(finding, customer_name, asset_display, None)
    msg = await bot.send_message(chat_id, message, disable_web_page_preview=True)
    alert.telegram_message_id = msg.message_id
    alert.state = "dispatched"
    alert.dispatched_at = datetime.now(timezone.utc)
    return True


async def _dispatch_batch(bot: Bot, chat_id: str, batch: AlertBatch, session) -> bool:
    customer = await session.get(Customer, batch.customer_id)
    customer_name = customer.name if customer else f"Customer#{batch.customer_id}"
    stmt = select(AlertQueue).where(AlertQueue.batch_id == batch.id)
    alerts = list((await session.execute(stmt)).scalars())
    summary = []
    for a in alerts:
        f = await session.get(Finding, a.finding_id)
        if not f:
            continue
        summary.append({
            "severity": f.severity.value,
            "ioc_value": (f.ioc_value.upper() if f.ioc_type == "cve_id" else f.ioc_value[:50]),
            "asset_display": f.matched_asset or "-",
            "finding_id": f.id,
        })
    message = format_alert_batch(batch, customer_name, summary)
    msg = await bot.send_message(chat_id, message, disable_web_page_preview=True)
    batch.telegram_message_id = msg.message_id
    batch.dispatched_at = datetime.now(timezone.utc)
    return True


async def _mark_failed(session, alert_id: int, error: str, settings) -> None:
    alert = await session.get(AlertQueue, alert_id)
    if not alert:
        return
    alert.attempt_count = (alert.attempt_count or 0) + 1
    alert.last_error = error[:500]
    if alert.attempt_count >= settings.alert_retry_max_attempts:
        alert.state = "failed"
        alert.next_retry_at = None
    else:
        alert.next_retry_at = (
            datetime.now(timezone.utc) + timedelta(seconds=settings.alert_retry_backoff_seconds)
        )
    await session.commit()


async def dispatch_loop_once(bot: Bot, settings) -> dict:
    stats = {"single_sent": 0, "batches_sent": 0, "failed": 0, "retried": 0}

    async with async_session() as session:
        now = datetime.now(timezone.utc)
        stmt = select(AlertQueue).where(
            AlertQueue.state == "pending",
            or_(
                AlertQueue.next_retry_at.is_(None),
                AlertQueue.next_retry_at <= now,
            ),
        ).order_by(AlertQueue.created_at.asc()).limit(50)
        pending = list((await session.execute(stmt)).scalars())

        by_customer: dict[int, list[AlertQueue]] = {}
        for a in pending:
            by_customer.setdefault(a.customer_id, []).append(a)

        for customer_id, alerts in by_customer.items():
            batch_id = await check_and_batch(
                session, customer_id,
                settings.alert_batch_trigger_count,
                settings.alert_batch_window_seconds,
            )
            if batch_id:
                batch = await session.get(AlertBatch, batch_id)
                try:
                    await _dispatch_batch(bot, settings.telegram_alert_chat_id, batch, session)
                    await session.commit()
                    stats["batches_sent"] += 1
                except TelegramRetryAfter as e:
                    logger.warning("Telegram flood: retry in %ds", e.retry_after)
                    for a in alerts:
                        await _mark_failed(session, a.id, f"batch flood: retry {e.retry_after}s", settings)
                    stats["failed"] += len(alerts)
                except TelegramAPIError as e:
                    logger.error("Batch dispatch failed: %s", e)
                    for a in alerts:
                        await _mark_failed(session, a.id, str(e), settings)
                    stats["failed"] += len(alerts)
            else:
                for a in alerts:
                    if a.attempt_count and a.attempt_count > 0:
                        stats["retried"] += 1
                    try:
                        await _dispatch_single(bot, settings.telegram_alert_chat_id, a, session)
                        await session.commit()
                        stats["single_sent"] += 1
                    except TelegramRetryAfter as e:
                        await _mark_failed(session, a.id, f"flood: retry {e.retry_after}s", settings)
                        stats["failed"] += 1
                    except TelegramAPIError as e:
                        await _mark_failed(session, a.id, str(e), settings)
                        stats["failed"] += 1

    return stats


async def run_forever() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )
    settings = get_settings()
    if not settings.telegram_alert_bot_token:
        logger.error("TELEGRAM_ALERT_BOT_TOKEN missing; exiting")
        return 2
    if not settings.telegram_alert_chat_id:
        logger.error("TELEGRAM_ALERT_CHAT_ID missing; exiting")
        return 2

    bot = Bot(token=settings.telegram_alert_bot_token)
    logger.info("Bot 1 (alert) starting; poll every %ds", POLL_INTERVAL_SECONDS)
    try:
        while True:
            try:
                stats = await dispatch_loop_once(bot, settings)
                if any(stats.values()):
                    logger.info("Loop: %s", stats)
            except Exception:
                logger.exception("Dispatch loop error")
            await asyncio.sleep(POLL_INTERVAL_SECONDS)
    finally:
        await bot.session.close()
    return 0
