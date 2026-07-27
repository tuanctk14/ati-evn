"""Approve an auto-detected campaign via agent."""
from __future__ import annotations

from datetime import datetime, timezone

from ati_evn.agent.tools._action_base import pending_confirmation, register_action_tool
from ati_evn.agent.tools._base import tool_error
from ati_evn.db.models import Campaign, CampaignStatus
from ati_evn.db.session import async_session


@register_action_tool(
    name="confirm_campaign",
    destructive=True,
    description=(
        "Approve an auto-detected campaign (status -> confirmed). Analyst "
        "reviewed and validates it's a real coordinated attack."
    ),
    parameters={
        "type": "object",
        "properties": {
            "campaign_id": {"type": "integer"},
            "note": {"type": "string"},
        },
        "required": ["campaign_id"],
    },
)
async def confirm_campaign(campaign_id: int, note: str = "", confirmed: bool = False) -> dict:
    async with async_session() as session:
        c = await session.get(Campaign, campaign_id)
        if not c:
            return tool_error(f"Campaign #{campaign_id} not found")
        current = c.status
        finding_count = c.finding_count
        confidence = c.confidence

    if current == CampaignStatus.CONFIRMED.value:
        return tool_error(f"Campaign #{campaign_id} already confirmed")

    if not confirmed:
        return pending_confirmation({
            "action": "confirm_campaign",
            "campaign_id": campaign_id,
            "current_status": current,
            "finding_count": finding_count,
            "confidence": confidence,
        })

    async with async_session() as session:
        camp = await session.get(Campaign, campaign_id)
        camp.status = CampaignStatus.CONFIRMED.value
        camp.reviewed_by = "agent"
        camp.reviewed_at = datetime.now(timezone.utc)
        if note:
            camp.review_notes = note[:2000]
        camp.updated_at = datetime.now(timezone.utc)
        await session.commit()

    return {"status": "confirmed", "campaign_id": campaign_id}
