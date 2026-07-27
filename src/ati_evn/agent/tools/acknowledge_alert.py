"""Acknowledge an AlertQueue entry via agent.

Schema note: AlertQueue.state is a plain String (not an enum) -- the
real /ack command (telegram/commands/action.py) sets it to the literal
string "acknowledged" with no dedicated timestamp/note column. This
tool follows the same convention rather than inventing new columns;
the note is only echoed back in the tool result, not persisted (same
limitation the existing /ack command already has).
"""
from __future__ import annotations

from ati_evn.agent.tools._action_base import pending_confirmation, register_action_tool
from ati_evn.agent.tools._base import tool_error
from ati_evn.db.models import AlertQueue
from ati_evn.db.session import async_session


@register_action_tool(
    name="acknowledge_alert",
    destructive=True,
    description="Mark an AlertQueue entry as acknowledged -- analyst handled the alert externally.",
    parameters={
        "type": "object",
        "properties": {
            "alert_id": {"type": "integer"},
            "note": {"type": "string"},
        },
        "required": ["alert_id"],
    },
)
async def acknowledge_alert(alert_id: int, note: str = "", confirmed: bool = False) -> dict:
    async with async_session() as session:
        alert = await session.get(AlertQueue, alert_id)
        if not alert:
            return tool_error(f"Alert #{alert_id} not found")
        current_state = alert.state
        finding_id = alert.finding_id

    if not confirmed:
        return pending_confirmation({
            "action": "acknowledge_alert",
            "alert_id": alert_id,
            "current_state": current_state,
            "finding_id": finding_id,
        })

    async with async_session() as session:
        a = await session.get(AlertQueue, alert_id)
        if not a:
            return tool_error(f"Alert #{alert_id} not found")
        a.state = "acknowledged"
        await session.commit()

    return {"status": "acknowledged", "alert_id": alert_id, "note": note}
