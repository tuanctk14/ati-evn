"""Daily TTL enforcement for ThreatIndicators.

Actions per run:
1. Mark expired: status in (active, acknowledged) + expires_at < now
                 -> status='stale'
2. Archive stale: status='stale' + updated_at < now-30d
                 -> status='archived'

Idempotent, safe to run manually or via scheduler.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import update

from ati_evn.db.models import ThreatIndicator
from ati_evn.db.session import async_session

logger = logging.getLogger("ati_evn.alerts.ti_ttl_worker")

ARCHIVE_STALE_AFTER_DAYS = 30


async def enforce_ttl() -> dict:
    """Mark expired -> stale, mark old stale -> archived."""
    now = datetime.now(timezone.utc)
    archive_cutoff = now - timedelta(days=ARCHIVE_STALE_AFTER_DAYS)

    stats = {"marked_stale": 0, "marked_archived": 0}

    async with async_session() as session:
        result = await session.execute(
            update(ThreatIndicator)
            .where(
                ThreatIndicator.status.in_(["active", "acknowledged"]),
                ThreatIndicator.expires_at < now,
            )
            .values(status="stale", updated_at=now)
            .returning(ThreatIndicator.id)
        )
        stats["marked_stale"] = len(list(result))

        result = await session.execute(
            update(ThreatIndicator)
            .where(
                ThreatIndicator.status == "stale",
                ThreatIndicator.updated_at < archive_cutoff,
            )
            .values(status="archived", updated_at=now)
            .returning(ThreatIndicator.id)
        )
        stats["marked_archived"] = len(list(result))

        await session.commit()

    logger.info("TI TTL enforcement: %s", stats)
    return stats


async def run_daily_ttl() -> dict:
    """Scheduler entry point."""
    try:
        return await enforce_ttl()
    except Exception as e:
        logger.exception("TTL enforcement failed: %s", e)
        return {"success": False, "error": str(e)[:500]}
