"""Load the Finding or ThreatIndicator an AlertQueue/Alert row points to.

Polymorphic (slice 15A): exactly one of finding_id / threat_indicator_id
is set on AlertQueue/Alert, enforced by a DB CHECK constraint.
"""
from __future__ import annotations

from ati_evn.db.models import Finding, ThreatIndicator
from ati_evn.db.session import async_session


async def load_alert_entity(alert_queue_row) -> dict | None:
    """Return {"entity_type": "finding"|"threat_indicator", "entity": obj}
    for the row's non-null FK, or None if the referenced row is missing."""
    if alert_queue_row.finding_id:
        async with async_session() as session:
            f = await session.get(Finding, alert_queue_row.finding_id)
        if not f:
            return None
        return {"entity_type": "finding", "entity": f}

    if alert_queue_row.threat_indicator_id:
        async with async_session() as session:
            ti = await session.get(ThreatIndicator, alert_queue_row.threat_indicator_id)
        if not ti:
            return None
        return {"entity_type": "threat_indicator", "entity": ti}

    return None
