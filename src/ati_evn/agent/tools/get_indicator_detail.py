"""get_indicator_detail — full detail of one ThreatIndicator."""
from __future__ import annotations

from ati_evn.agent.tools._action_base import register_action_tool
from ati_evn.agent.tools._base import tool_error
from ati_evn.db.models import Customer, ThreatIndicator
from ati_evn.db.session import async_session


@register_action_tool(
    name="get_indicator_detail",
    destructive=False,
    description=(
        "Get full detail of one ThreatIndicator including notes, "
        "acknowledgement state, source-specific metadata."
    ),
    parameters={
        "type": "object",
        "properties": {
            "indicator_id": {"type": "integer"},
        },
        "required": ["indicator_id"],
    },
)
async def get_indicator_detail(indicator_id: int) -> dict:
    async with async_session() as session:
        ti = await session.get(ThreatIndicator, indicator_id)
        if not ti:
            return tool_error(f"ThreatIndicator #{indicator_id} not found")

        customer = None
        if ti.customer_id:
            c = await session.get(Customer, ti.customer_id)
            if c:
                customer = {"id": c.id, "name": c.name, "short_code": c.short_code}

    return {
        "id": ti.id,
        "type": ti.indicator_type,
        "value": ti.indicator_value,
        "title": ti.title,
        "detection_reason": ti.detection_reason,
        "severity": ti.severity.value if hasattr(ti.severity, "value") else str(ti.severity),
        "customer": customer,
        "matched_asset": ti.matched_asset_value,
        "source": ti.source,
        "sources": ti.sources or [],
        "source_count": ti.source_count,
        "source_entity_type": ti.source_entity_type,
        "source_entity_id": ti.source_entity_id,
        "status": ti.status,
        "acknowledged": bool(ti.acknowledged_at),
        "acknowledged_at": ti.acknowledged_at.isoformat() if ti.acknowledged_at else None,
        "acknowledged_by": ti.acknowledged_by,
        "acknowledgement_note": ti.acknowledgement_note,
        "notes": (ti.notes or [])[-10:],
        "first_seen": ti.first_seen.isoformat() if ti.first_seen else None,
        "last_seen": ti.last_seen.isoformat() if ti.last_seen else None,
        "expires_at": ti.expires_at.isoformat() if ti.expires_at else None,
        "metadata": ti.metadata_ or {},
    }
