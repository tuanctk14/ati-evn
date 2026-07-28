"""When >=N alerts pending for the same customer within window, merge into
a single batch dispatch.

Trigger check happens when dispatcher pulls next pending alert:
  1. Count pending alerts for this customer in last N seconds
  2. If >= threshold, create AlertBatch, associate all pending
     same-customer alerts, dispatch as batch message
  3. Else, dispatch as individual message
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ati_evn.db.models import AlertBatch, AlertQueue, Finding, ThreatIndicator, _utcnow


async def check_and_batch(
    session: AsyncSession, customer_id: int, trigger_count: int, window_seconds: int,
) -> int | None:
    """Return AlertBatch.id if batched, None if not enough for batch.

    Marks ALL pending alerts for this customer within window as batched,
    associates them with a new AlertBatch row.
    """
    cutoff = _utcnow() - timedelta(seconds=window_seconds)
    stmt = select(AlertQueue).where(
        AlertQueue.customer_id == customer_id,
        AlertQueue.state == "pending",
        AlertQueue.created_at >= cutoff,
    )
    pending = list((await session.execute(stmt)).scalars())
    if len(pending) < trigger_count:
        return None

    # Aggregate severity counts -- polymorphic: alert.finding_id XOR
    # alert.threat_indicator_id is set (slice 15A).
    sev_counts: dict[str, int] = {}
    for alert in pending:
        if alert.finding_id:
            entity = await session.get(Finding, alert.finding_id)
        else:
            entity = await session.get(ThreatIndicator, alert.threat_indicator_id)
        sev = entity.severity.value if entity else "UNKNOWN"
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    batch = AlertBatch(
        customer_id=customer_id,
        finding_count=len(pending),
        severities=sev_counts,
    )
    session.add(batch)
    await session.flush()

    # Mark pending alerts as batched
    await session.execute(
        update(AlertQueue)
        .where(AlertQueue.id.in_([a.id for a in pending]))
        .values(state="batched", batch_id=batch.id)
    )
    await session.commit()
    return batch.id
