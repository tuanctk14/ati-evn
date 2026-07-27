"""Soft-delete an internal-source IOC via agent.

Only source='internal' Detections are deletable. Linked Findings are
retained as evidence -- only the IOC entry is hidden. If the IOC has
linked findings, the confirmation summary surfaces that count as impact.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import func, select

from ati_evn.agent.tools._action_base import pending_confirmation, register_action_tool
from ati_evn.agent.tools._base import tool_error
from ati_evn.db.models import Detection, Finding
from ati_evn.db.session import async_session


@register_action_tool(
    name="delete_ioc",
    destructive=True,
    description=(
        "Soft-delete an internal-source IOC (Detection). Linked Findings "
        "are retained as evidence, only the IOC entry is hidden."
    ),
    parameters={
        "type": "object",
        "properties": {"detection_id": {"type": "integer"}},
        "required": ["detection_id"],
    },
)
async def delete_ioc(detection_id: int, confirmed: bool = False) -> dict:
    async with async_session() as session:
        det = await session.get(Detection, detection_id)
        if not det:
            return tool_error(f"Detection #{detection_id} not found")
        if det.deleted_at:
            return tool_error(f"Detection #{detection_id} đã bị soft-delete từ trước.")
        if det.source != "internal":
            return tool_error(f"Detection #{detection_id} has source='{det.source}' -- only internal IOCs are deletable.")

        finding_count = (await session.execute(
            select(func.count(Finding.id)).where(Finding.ioc_type == det.ioc_type, Finding.ioc_value == det.ioc_value)
        )).scalar() or 0

    if not confirmed:
        return pending_confirmation({
            "action": "delete_ioc",
            "detection_id": detection_id,
            "ioc_type": det.ioc_type,
            "ioc_value": det.ioc_value,
            "impact": f"Also affects {finding_count} linked finding(s) (findings themselves are retained as evidence, only the IOC is hidden)",
        })

    async with async_session() as session:
        d = await session.get(Detection, detection_id)
        if not d:
            return tool_error(f"Detection #{detection_id} not found")
        d.deleted_at = datetime.now(timezone.utc)
        d.deleted_by = "agent"
        await session.commit()

    return {"status": "deleted", "detection_id": detection_id, "linked_findings_retained": finding_count}
