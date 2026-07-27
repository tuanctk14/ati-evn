"""Change a Finding's status via agent.

Schema note: FindingStatus real values are OPEN, ACKED ("acknowledged"),
CLOSED, FALSE_POSITIVE, EXPIRED -- there is no IN_PROGRESS or RESOLVED
value. Finding also has no updated_at column (unlike Campaign/Exposure),
so only the fields the model actually defines are touched.
"""
from __future__ import annotations

from datetime import datetime, timezone

from ati_evn.agent.tools._action_base import pending_confirmation, register_action_tool
from ati_evn.agent.tools._base import tool_error
from ati_evn.db.models import Finding, FindingStatus
from ati_evn.db.session import async_session


@register_action_tool(
    name="update_finding_status",
    destructive=True,
    description=(
        "Change a Finding's status. Valid values: OPEN (reopen), "
        "ACKED (acknowledged, investigating), CLOSED (resolved/fixed), "
        "FALSE_POSITIVE (not a real threat)."
    ),
    parameters={
        "type": "object",
        "properties": {
            "finding_id": {"type": "integer"},
            "new_status": {"type": "string", "enum": ["OPEN", "ACKED", "CLOSED", "FALSE_POSITIVE"]},
            "reason": {"type": "string", "description": "Reason for status change"},
        },
        "required": ["finding_id", "new_status"],
    },
)
async def update_finding_status(
    finding_id: int, new_status: str, reason: str = "", confirmed: bool = False,
) -> dict:
    async with async_session() as session:
        finding = await session.get(Finding, finding_id)
        if not finding:
            return tool_error(f"Finding #{finding_id} not found")
        current = finding.status.value if hasattr(finding.status, "value") else str(finding.status)
        title = finding.title

    try:
        new_enum = FindingStatus[new_status]
    except KeyError:
        return tool_error(f"Invalid status: {new_status}")

    if not confirmed:
        return pending_confirmation({
            "action": "update_finding_status",
            "finding_id": finding_id,
            "title": title[:80],
            "current_status": current,
            "new_status": new_status,
            "reason": reason,
        })

    now = datetime.now(timezone.utc)
    async with async_session() as session:
        f = await session.get(Finding, finding_id)
        if not f:
            return tool_error(f"Finding #{finding_id} not found")
        f.status = new_enum
        if new_enum == FindingStatus.CLOSED or new_enum == FindingStatus.FALSE_POSITIVE:
            f.closed_at = now
            f.closed_reason = reason or None
        elif new_enum == FindingStatus.OPEN:
            f.closed_at = None
            f.closed_reason = None
        if reason:
            meta = dict(f.metadata_ or {})
            history = meta.get("status_history") or []
            history.append({"from": current, "to": new_status, "reason": reason, "at": now.isoformat()})
            meta["status_history"] = history[-20:]
            f.metadata_ = meta
        await session.commit()

    return {
        "status": "updated",
        "finding_id": finding_id,
        "old_status": current,
        "new_status": new_status,
    }
