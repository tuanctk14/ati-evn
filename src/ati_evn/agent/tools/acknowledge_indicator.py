"""acknowledge_indicator — mark a ThreatIndicator as handled (analyst-facing).

Different from Finding close/mark_fp -- ThreatIndicator has no close/
reopen state, only acknowledged (it's a read-only signal, not a
patchable vulnerability).
"""
from __future__ import annotations

from datetime import datetime, timezone

from ati_evn.agent.tools._action_base import pending_confirmation, register_action_tool
from ati_evn.agent.tools._base import tool_error
from ati_evn.db.models import ThreatIndicator
from ati_evn.db.session import async_session


@register_action_tool(
    name="acknowledge_indicator",
    destructive=True,
    description=(
        "Mark a ThreatIndicator as acknowledged (analyst has seen and "
        "handled it). Different from Finding close/mark_fp -- TI has no "
        "close/reopen state, only acknowledged."
    ),
    parameters={
        "type": "object",
        "properties": {
            "indicator_id": {"type": "integer"},
            "note": {"type": "string"},
        },
        "required": ["indicator_id"],
    },
)
async def acknowledge_indicator(
    indicator_id: int, note: str = "", confirmed: bool = False,
) -> dict:
    async with async_session() as session:
        ti = await session.get(ThreatIndicator, indicator_id)
        if not ti:
            return tool_error(f"TI #{indicator_id} not found")
        if ti.acknowledged_at:
            return tool_error(
                f"TI #{indicator_id} already acknowledged at {ti.acknowledged_at.isoformat()}"
            )
        indicator_type = ti.indicator_type
        title = ti.title
        severity = ti.severity.value if hasattr(ti.severity, "value") else str(ti.severity)

    if not confirmed:
        return pending_confirmation({
            "action": "acknowledge_indicator",
            "indicator_id": indicator_id,
            "type": indicator_type,
            "title": title[:80],
            "severity": severity,
            "note": note[:100] if note else None,
        })

    now = datetime.now(timezone.utc)
    async with async_session() as session:
        t = await session.get(ThreatIndicator, indicator_id)
        if not t:
            return tool_error(f"TI #{indicator_id} not found")
        if t.acknowledged_at:
            return tool_error(
                f"TI #{indicator_id} already acknowledged at {t.acknowledged_at.isoformat()}"
            )
        t.acknowledged_at = now
        t.acknowledged_by = "agent"
        if note:
            t.acknowledgement_note = note[:500]
        t.status = "acknowledged"
        t.updated_at = now
        await session.commit()

    return {"status": "acknowledged", "indicator_id": indicator_id}
