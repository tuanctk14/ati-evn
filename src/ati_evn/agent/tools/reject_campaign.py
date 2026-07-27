"""Reject an auto-detected campaign as false-positive via agent."""
from __future__ import annotations

from datetime import datetime, timezone

from ati_evn.agent.tools._action_base import pending_confirmation, register_action_tool
from ati_evn.agent.tools._base import tool_error
from ati_evn.db.models import Campaign, CampaignStatus
from ati_evn.db.session import async_session


@register_action_tool(
    name="reject_campaign",
    destructive=True,
    description=(
        "Reject an auto-detected campaign as false-positive "
        "(status -> rejected)."
    ),
    parameters={
        "type": "object",
        "properties": {
            "campaign_id": {"type": "integer"},
            "reason": {"type": "string"},
        },
        "required": ["campaign_id", "reason"],
    },
)
async def reject_campaign(campaign_id: int, reason: str, confirmed: bool = False) -> dict:
    async with async_session() as session:
        c = await session.get(Campaign, campaign_id)
        if not c:
            return tool_error(f"Campaign #{campaign_id} not found")
        current = c.status

    if current == CampaignStatus.REJECTED.value:
        return tool_error(f"Campaign #{campaign_id} already rejected")

    if not confirmed:
        return pending_confirmation({
            "action": "reject_campaign",
            "campaign_id": campaign_id,
            "current_status": current,
            "reason": reason,
        })

    async with async_session() as session:
        camp = await session.get(Campaign, campaign_id)
        camp.status = CampaignStatus.REJECTED.value
        camp.reviewed_by = "agent"
        camp.reviewed_at = datetime.now(timezone.utc)
        camp.review_notes = reason[:2000]
        camp.updated_at = datetime.now(timezone.utc)
        await session.commit()

    return {"status": "rejected", "campaign_id": campaign_id}
