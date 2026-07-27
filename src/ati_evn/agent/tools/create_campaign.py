"""Manually group findings into a Campaign via agent."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select

from ati_evn.agent.tools._action_base import pending_confirmation, register_action_tool
from ati_evn.agent.tools._base import tool_error
from ati_evn.db.models import Campaign, CampaignFinding, CampaignStatus, Customer, Finding
from ati_evn.db.query_utils import customer_name_or_code_match
from ati_evn.db.session import async_session


@register_action_tool(
    name="create_campaign",
    destructive=True,
    description=(
        "Manually group findings into a Campaign. Use when auto-detection "
        "missed a pattern. Analyst provides finding_ids + customer. Created "
        "campaigns are pre-set to status=confirmed (analyst already validated)."
    ),
    parameters={
        "type": "object",
        "properties": {
            "finding_ids": {"type": "array", "items": {"type": "integer"}},
            "customer": {"type": "string"},
            "confidence": {"type": "number", "default": 0.85, "description": "0-1"},
            "technique_ids": {
                "type": "array",
                "items": {"type": "string"},
                "description": "ATT&CK technique IDs",
            },
        },
        "required": ["finding_ids", "customer"],
    },
)
async def create_campaign(
    finding_ids: list[int],
    customer: str,
    confidence: float = 0.85,
    technique_ids: list[str] | None = None,
    confirmed: bool = False,
) -> dict:
    technique_ids = technique_ids or []
    if len(finding_ids) < 2:
        return tool_error("Campaign requires at least 2 findings")

    async with async_session() as session:
        cr = await session.execute(
            select(Customer.id, Customer.name).where(
                customer_name_or_code_match(customer),
                Customer.deleted_at.is_(None),
            ).limit(1)
        )
        r = cr.first()
        if not r:
            return tool_error(f"Customer '{customer}' not found")
        customer_id = r.id
        customer_name = r.name

        f_stmt = select(Finding).where(
            Finding.id.in_(finding_ids),
            Finding.customer_id == customer_id,
        )
        found = list((await session.execute(f_stmt)).scalars())
        found_ids = [f.id for f in found]
        missing = set(finding_ids) - set(found_ids)
        if missing:
            return tool_error(f"Findings not found or wrong customer: {sorted(missing)}")

        preview_titles = [f.title[:60] for f in found[:5]]
        asset_count = len({f.matched_asset for f in found if f.matched_asset})

    if not confirmed:
        return pending_confirmation({
            "action": "create_campaign",
            "customer": customer_name,
            "finding_count": len(finding_ids),
            "preview": preview_titles,
            "confidence": confidence,
            "technique_ids": technique_ids,
        })

    now = datetime.now(timezone.utc)
    earliest = min((f.first_seen for f in found if f.first_seen), default=now)
    latest = max((f.last_seen or f.first_seen for f in found if f.first_seen), default=now)
    severities: dict[str, int] = {}
    for f in found:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        severities[sev] = severities.get(sev, 0) + 1

    async with async_session() as session:
        camp = Campaign(
            customer_id=customer_id,
            window_start=earliest,
            window_end=latest,
            finding_count=len(found),
            asset_count=asset_count,
            technique_ids=technique_ids,
            severities=severities,
            confidence=confidence,
            detection_reason="Manually created by analyst via agent tool",
            status=CampaignStatus.CONFIRMED.value,
        )
        session.add(camp)
        await session.flush()
        campaign_id = camp.id

        for fid in found_ids:
            session.add(CampaignFinding(campaign_id=campaign_id, finding_id=fid))

        await session.commit()

    return {
        "status": "created",
        "campaign_id": campaign_id,
        "customer": customer_name,
        "finding_count": len(found),
    }
