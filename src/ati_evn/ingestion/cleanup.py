"""Mark PENDING ingestion sessions as EXPIRED after 24h."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import update

from ati_evn.db.models import IngestionSession
from ati_evn.db.session import async_session

logger = logging.getLogger("ati_evn.ingestion.cleanup")


async def cleanup_expired_ingestions() -> int:
    """Return count expired."""
    now = datetime.now(timezone.utc)
    async with async_session() as session:
        result = await session.execute(
            update(IngestionSession)
            .where(
                IngestionSession.status == "pending",
                IngestionSession.expires_at < now,
            )
            .values(status="expired")
        )
        await session.commit()
        n = result.rowcount or 0
        if n:
            logger.info("Marked %d ingestion sessions as EXPIRED", n)
        return n
