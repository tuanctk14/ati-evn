"""Full detail for one Campaign including linked findings."""
from sqlalchemy import select

from ati_evn.agent.tools._base import register_tool, tool_error
from ati_evn.db.models import Campaign, CampaignFinding, Customer, Finding
from ati_evn.db.session import async_session
from ati_evn.enrichment.attack_catalog import get_technique_name, is_technique_revoked


@register_tool(
    name="get_campaign_detail",
    description=(
        "Get full detail of a Campaign by ID including all linked "
        "Findings, technique names, kill chain, and confidence breakdown."
    ),
    parameters={
        "type": "object",
        "properties": {
            "campaign_id": {"type": "integer",
                             "description": "Campaign ID"},
        },
        "required": ["campaign_id"],
    },
)
async def get_campaign_detail(campaign_id: int) -> dict:
    async with async_session() as session:
        c = await session.get(Campaign, campaign_id)
        if not c:
            return tool_error(
                f"Campaign #{campaign_id} not found",
                hint="Try search_campaigns to list available IDs",
            )
        customer = await session.get(Customer, c.customer_id)

        technique_details = [
            {
                "id": tid,
                "name": get_technique_name(tid),
                "revoked": is_technique_revoked(tid),
            }
            for tid in (c.technique_ids or [])
        ]

        fnd_stmt = select(Finding).join(
            CampaignFinding, Finding.id == CampaignFinding.finding_id,
        ).where(CampaignFinding.campaign_id == c.id)
        fnds = list((await session.execute(fnd_stmt)).scalars())
        findings_out = [
            {
                "id": f.id,
                "ioc_type": f.ioc_type,
                "ioc_value": f.ioc_value,
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "status": f.status.value if hasattr(f.status, "value") else str(f.status),
                "matched_asset": f.matched_asset or "",
                "first_seen": f.first_seen.isoformat() if f.first_seen else None,
            }
            for f in fnds
        ]

        return {
            "campaign": {
                "id": c.id,
                "customer": customer.name if customer else None,
                "customer_id": c.customer_id,
                "status": c.status,
                "confidence": round(c.confidence, 3),
                "window_start": c.window_start.isoformat() if c.window_start else None,
                "window_end": c.window_end.isoformat() if c.window_end else None,
                "finding_count": c.finding_count,
                "asset_count": c.asset_count,
                "technique_ids": c.technique_ids or [],
                "tactic_ids": c.tactic_ids or [],
                "source_ids": c.source_ids or [],
                "severities": c.severities or {},
                "detection_reason": c.detection_reason,
                "reviewed_by": c.reviewed_by,
                "reviewed_at": c.reviewed_at.isoformat() if c.reviewed_at else None,
                "review_notes": c.review_notes,
            },
            "techniques": technique_details,
            "findings": findings_out,
        }
