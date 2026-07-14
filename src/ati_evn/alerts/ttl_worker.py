"""Background job: transition Finding.status -> EXPIRED when linked
internal-source Detection has expires_at passed.

Only affects Findings whose Detection.source == 'internal'.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select, update

from ati_evn.db.models import Detection, Finding, FindingStatus
from ati_evn.db.session import async_session


async def run_ttl_check_once() -> int:
    """Return count of findings transitioned."""
    now = datetime.now(timezone.utc)
    async with async_session() as session:
        # Find Detections that are expired AND linked to still-open Findings
        stmt = select(Detection.finding_id).where(
            Detection.expires_at.is_not(None),
            Detection.expires_at <= now,
            Detection.source == "internal",
            Detection.finding_id.is_not(None),
        ).distinct()
        finding_ids = [r[0] for r in await session.execute(stmt)]
        if not finding_ids:
            return 0

        result = await session.execute(
            update(Finding)
            .where(Finding.id.in_(finding_ids), Finding.status == FindingStatus.OPEN)
            .values(status=FindingStatus.EXPIRED,
                    closed_at=now,
                    closed_by="ttl_worker",
                    closed_reason="Internal IOC TTL expired")
            .returning(Finding.id)
        )
        transitioned = list(result.scalars())
        await session.commit()
        return len(transitioned)
