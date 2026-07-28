"""add_indicator_note — append an investigation note to a ThreatIndicator."""
from __future__ import annotations

from datetime import datetime, timezone

from ati_evn.agent.tools._action_base import pending_confirmation, register_action_tool
from ati_evn.agent.tools._base import tool_error
from ati_evn.db.models import ThreatIndicator
from ati_evn.db.session import async_session


@register_action_tool(
    name="add_indicator_note",
    destructive=True,
    description=(
        "Append an investigation note to a ThreatIndicator. Notes are "
        "append-only history for audit trail."
    ),
    parameters={
        "type": "object",
        "properties": {
            "indicator_id": {"type": "integer"},
            "note": {"type": "string"},
        },
        "required": ["indicator_id", "note"],
    },
)
async def add_indicator_note(
    indicator_id: int, note: str, confirmed: bool = False,
) -> dict:
    note = (note or "").strip()[:800]
    if not note:
        return tool_error("Note text cannot be empty")

    async with async_session() as session:
        ti = await session.get(ThreatIndicator, indicator_id)
        if not ti:
            return tool_error(f"TI #{indicator_id} not found")
        title = ti.title

    if not confirmed:
        return pending_confirmation({
            "action": "add_indicator_note",
            "indicator_id": indicator_id,
            "title": title[:80],
            "note_preview": note[:100],
        })

    now = datetime.now(timezone.utc)
    async with async_session() as session:
        t = await session.get(ThreatIndicator, indicator_id)
        if not t:
            return tool_error(f"TI #{indicator_id} not found")
        notes = list(t.notes or [])
        notes.append({"timestamp": now.isoformat(), "author": "agent", "text": note})
        t.notes = notes[-50:]
        t.updated_at = now
        await session.commit()
        total_notes = len(t.notes)

    return {"status": "note_added", "indicator_id": indicator_id, "total_notes": total_notes}
