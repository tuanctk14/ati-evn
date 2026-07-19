"""Per-feed scheduler + catch-up-on-startup logic.

One APScheduler job per feed, at feed-specific interval. Each job calls
run_feed_once(feed_name) which computes the fetch window, invokes the
fetcher instance's .fetch(since_hours), ingests the result through the
same pipeline scripts/run_fetchers.py uses, records history, and — after
enough consecutive failures — pings Bot 1.

Fetchers are NOT uniform: NVDFetcher().fetch() returns
{"raw_iocs", "cpe_rows", "cwe_rows"} and is ingested via
ingest_cve_batch(); the four abuse.ch fetchers return list[RawIOC]
directly and go through ingest_raw_iocs(). This module dispatches on
feed name rather than assuming a single fetch_fn(since_hours) -> dict
shape (see scripts/run_fetchers.py for the reference pattern).
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from ati_evn.config import get_settings
from ati_evn.db.models import FeedRunHistory
from ati_evn.db.session import async_session
from ati_evn.fetchers.base import IOCFetcher
from ati_evn.ingest.pipeline import ingest_cve_batch, ingest_raw_iocs

logger = logging.getLogger("ati_evn.fetchers.scheduler")


@dataclass
class FeedSpec:
    name: str
    interval_min: int
    fetcher_cls: type[IOCFetcher]
    is_cve: bool  # NVD-shaped (dict result, ingest_cve_batch) vs RawIOC list


def _get_feed_specs() -> list[FeedSpec]:
    """Import fetcher classes lazily to avoid circular imports at module load."""
    from ati_evn.fetchers.cve.nvd import NVDFetcher
    from ati_evn.fetchers.ioc.feodo import FeodoFetcher
    from ati_evn.fetchers.ioc.malwarebazaar import MalwareBazaarFetcher
    from ati_evn.fetchers.ioc.threatfox import ThreatFoxFetcher
    from ati_evn.fetchers.ioc.urlhaus import URLhausFetcher

    s = get_settings()
    return [
        FeedSpec("nvd", s.fetcher_nvd_interval_min, NVDFetcher, is_cve=True),
        FeedSpec("threatfox", s.fetcher_threatfox_interval_min, ThreatFoxFetcher, is_cve=False),
        FeedSpec("malwarebazaar", s.fetcher_malwarebazaar_interval_min, MalwareBazaarFetcher, is_cve=False),
        FeedSpec("urlhaus", s.fetcher_urlhaus_interval_min, URLhausFetcher, is_cve=False),
        FeedSpec("feodo", s.fetcher_feodo_interval_min, FeodoFetcher, is_cve=False),
    ]


def _interval_for(feed_name: str) -> int:
    for spec in _get_feed_specs():
        if spec.name == feed_name:
            return spec.interval_min
    return 60


async def _get_last_success(feed_name: str) -> datetime | None:
    async with async_session() as session:
        row = await session.execute(
            select(FeedRunHistory.completed_at)
            .where(FeedRunHistory.feed_name == feed_name, FeedRunHistory.status == "success")
            .order_by(FeedRunHistory.started_at.desc())
            .limit(1)
        )
        return row.scalar_one_or_none()


async def _get_consecutive_failure_count(feed_name: str) -> int:
    """Count consecutive failures since the last success (or all failures
    if the feed has never succeeded), most-recent-first."""
    async with async_session() as session:
        row = await session.execute(
            select(FeedRunHistory.status)
            .where(FeedRunHistory.feed_name == feed_name)
            .order_by(FeedRunHistory.started_at.desc())
            .limit(10)
        )
        recents = [r[0] for r in row]
    count = 0
    for s in recents:
        if s == "success":
            break
        if s == "failure":
            count += 1
    return count


async def _record_run(
    feed_name: str,
    started_at: datetime,
    window_start: datetime | None,
    window_end: datetime | None,
    status: str,
    added: int = 0,
    updated: int = 0,
    error: str | None = None,
    trigger_reason: str = "scheduled",
) -> None:
    async with async_session() as session:
        session.add(FeedRunHistory(
            feed_name=feed_name,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
            status=status,
            window_start=window_start,
            window_end=window_end,
            detections_added=added,
            detections_updated=updated,
            error_message=error,
            trigger_reason=trigger_reason,
        ))
        await session.commit()


async def _notify_feed_failure(
    feed_name: str, error: str, failure_count: int, last_success: datetime | None,
) -> None:
    """Send Bot 1 alert about repeated feed failures."""
    from aiogram import Bot
    from aiogram.exceptions import TelegramAPIError

    settings = get_settings()
    if not settings.telegram_alert_bot_token or not settings.telegram_alert_chat_id:
        logger.warning("Feed %s failed %dx but alert bot not configured", feed_name, failure_count)
        return

    if last_success:
        age = datetime.now(timezone.utc) - last_success
        age_str = f"{age.total_seconds() / 3600:.1f}h ago"
    else:
        age_str = "never (first-time fetch)"

    next_retry = datetime.now(timezone.utc) + timedelta(minutes=_interval_for(feed_name))

    text = (
        f"🔴 Feed '{feed_name}' failed {failure_count} times in a row\n"
        f"Last error: {error[:300]}\n"
        f"Last successful fetch: {age_str}\n"
        f"Next retry: {next_retry.strftime('%Y-%m-%d %H:%M UTC')}"
    )
    bot = Bot(token=settings.telegram_alert_bot_token)
    try:
        await bot.send_message(settings.telegram_alert_chat_id, text, disable_web_page_preview=True)
    except TelegramAPIError as e:
        logger.error("Failed to send feed failure alert: %s", e)
    finally:
        await bot.session.close()


async def run_feed_once(feed_name: str, trigger_reason: str = "scheduled") -> dict:
    """Fetch + ingest one feed. Handles window computation, history
    recording, and failure notification. Returns a stats dict."""
    settings = get_settings()
    specs = {s.name: s for s in _get_feed_specs()}
    if feed_name not in specs:
        return {"error": f"Unknown feed: {feed_name}"}
    spec = specs[feed_name]

    started_at = datetime.now(timezone.utc)
    last_success = await _get_last_success(feed_name)

    if last_success is None:
        window_start = started_at - timedelta(hours=settings.fetcher_default_first_window_hours)
    else:
        window_start = last_success - timedelta(hours=settings.fetcher_window_buffer_hours)
    window_end = started_at

    since_hours = int((window_end - window_start).total_seconds() / 3600) + 1
    since_hours = max(1, min(since_hours, 168))  # cap at 1 week

    logger.info(
        "[%s] Fetching (%s) — window %s -> %s (%dh)",
        feed_name, trigger_reason,
        window_start.strftime("%Y-%m-%d %H:%M"), window_end.strftime("%Y-%m-%d %H:%M"),
        since_hours,
    )

    fetcher = spec.fetcher_cls()
    if not fetcher.is_configured():
        msg = f"{feed_name}: missing API key, skipping"
        logger.warning(msg)
        await _record_run(
            feed_name, started_at, window_start, window_end,
            "skipped", error=msg, trigger_reason=trigger_reason,
        )
        return {"status": "skipped", "error": msg}

    try:
        if spec.is_cve:
            result = await fetcher.fetch(since_hours=since_hours)
            async with async_session() as session:
                stats = await ingest_cve_batch(session, result)
                await session.commit()
        else:
            raw_iocs = await fetcher.fetch(since_hours=since_hours)
            async with async_session() as session:
                stats = await ingest_raw_iocs(session, raw_iocs)
                await session.commit()

        added = stats.inserted
        updated = stats.deduped  # dedup bumps last_seen on an existing row — the closest analogue to "updated" here
        await _record_run(
            feed_name, started_at, window_start, window_end,
            "success", added, updated, trigger_reason=trigger_reason,
        )
        logger.info("[%s] Fetch OK: %d added, %d updated (deduped)", feed_name, added, updated)
        return {"status": "success", "added": added, "updated": updated}
    except Exception as e:
        err_msg = f"{type(e).__name__}: {str(e)[:400]}"
        logger.exception("[%s] Fetch failed: %s", feed_name, e)
        await _record_run(
            feed_name, started_at, window_start, window_end,
            "failure", error=err_msg, trigger_reason=trigger_reason,
        )

        fail_count = await _get_consecutive_failure_count(feed_name)
        if fail_count >= settings.fetcher_failure_alert_threshold:
            await _notify_feed_failure(feed_name, err_msg, fail_count, last_success)
        return {"status": "failure", "error": err_msg}


async def startup_catchup() -> dict:
    """Run at Bot 2 startup. For each feed, decide immediate-fetch vs
    wait-for-next-scheduled-run based on last_fetched_at. Returns a
    summary dict; each feed's actual fetch (if triggered) runs as a
    background task so this doesn't block Bot 2 startup."""
    settings = get_settings()
    if not settings.fetcher_scheduler_enabled:
        logger.info("Fetcher scheduler disabled via config; skipping startup catch-up")
        return {"disabled": True}

    summary: dict[str, str] = {}
    now = datetime.now(timezone.utc)
    for spec in _get_feed_specs():
        last = await _get_last_success(spec.name)
        interval = timedelta(minutes=spec.interval_min)
        if last is None:
            logger.info(
                "[%s] last_fetched=NEVER, triggering initial fetch (default %dh window)",
                spec.name, settings.fetcher_default_first_window_hours,
            )
            asyncio.create_task(run_feed_once(spec.name, trigger_reason="startup_initial"))
            summary[spec.name] = "initial"
        elif now - last > interval:
            age_h = (now - last).total_seconds() / 3600
            logger.info(
                "[%s] last_fetched=%s (%.1fh ago, interval=%dmin), triggering catch-up",
                spec.name, last.strftime("%Y-%m-%d %H:%M"), age_h, spec.interval_min,
            )
            asyncio.create_task(run_feed_once(spec.name, trigger_reason="startup_catchup"))
            summary[spec.name] = "catchup"
        else:
            age_m = (now - last).total_seconds() / 60
            logger.info(
                "[%s] last_fetched=%s (%.1fmin ago, interval=%dmin), waiting until next scheduled",
                spec.name, last.strftime("%Y-%m-%d %H:%M"), age_m, spec.interval_min,
            )
            summary[spec.name] = "waiting"
    return summary


def register_feed_jobs(scheduler) -> int:
    """Register one APScheduler job per feed. Return count registered."""
    settings = get_settings()
    if not settings.fetcher_scheduler_enabled:
        logger.info("Fetcher scheduler disabled; no jobs registered")
        return 0
    count = 0
    for spec in _get_feed_specs():
        job_id = f"fetcher_{spec.name}"
        scheduler.add_job(
            run_feed_once,
            "interval",
            minutes=spec.interval_min,
            args=[spec.name, "scheduled"],
            id=job_id,
            # Don't fire immediately when registering — startup_catchup
            # handles the "should we fetch right now" decision separately.
            next_run_time=datetime.now(timezone.utc) + timedelta(minutes=spec.interval_min),
        )
        logger.info("Registered fetcher job '%s' at %dmin interval", job_id, spec.interval_min)
        count += 1
    return count
