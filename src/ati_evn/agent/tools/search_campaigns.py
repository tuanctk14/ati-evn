"""search_campaigns tool for agent.

Filters: customer (name/code), status, since_days, min_confidence, limit.
Returns list of campaign summary dicts.
"""
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from ati_evn.agent.tools._base import register_tool, tool_error
from ati_evn.db.models import Campaign, Customer
from ati_evn.db.query_utils import customer_name_or_code_match
from ati_evn.db.session import async_session


@register_tool(
    name="search_campaigns",
    description=(
        "Search detected attack Campaigns (clusters of Findings). "
        "Filters: customer name/code, status, recency, min confidence. "
        "Returns list of campaign summaries with technique IDs."
    ),
    parameters={
        "type": "object",
        "properties": {
            "customer": {"type": "string",
                         "description": "Customer name or short code"},
            "status": {"type": "string", "enum":
                       ["candidate", "confirmed", "rejected", "expired"],
                       "description": "Default: candidate"},
            "since_days": {"type": "integer",
                           "description": "Only campaigns created within N days"},
            "min_confidence": {"type": "number",
                                "description": "Minimum confidence 0-1"},
            "limit": {"type": "integer", "default": 10,
                      "description": "Max results (hard cap 20)"},
        },
        "required": [],
    },
)
async def search_campaigns(
    customer: str | None = None,
    status: str = "candidate",
    since_days: int | None = None,
    min_confidence: float | None = None,
    limit: int = 10,
) -> dict:
    limit = min(max(limit, 1), 20)
    async with async_session() as session:
        stmt = select(Campaign).where(Campaign.status == status)
        count_stmt = select(func.count(Campaign.id)).where(
            Campaign.status == status
        )
        if customer:
            cust_row = await session.execute(
                select(Customer.id).where(customer_name_or_code_match(customer))
                .limit(1)
            )
            cust_id = cust_row.scalar_one_or_none()
            if not cust_id:
                return tool_error(f"Customer '{customer}' not found",
                                   hint="Try a shorter name or short code (e.g. NPC, CPC)")
            stmt = stmt.where(Campaign.customer_id == cust_id)
            count_stmt = count_stmt.where(Campaign.customer_id == cust_id)
        if since_days is not None:
            cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)
            stmt = stmt.where(Campaign.created_at >= cutoff)
            count_stmt = count_stmt.where(Campaign.created_at >= cutoff)
        if min_confidence is not None:
            stmt = stmt.where(Campaign.confidence >= min_confidence)
            count_stmt = count_stmt.where(Campaign.confidence >= min_confidence)

        total = (await session.execute(count_stmt)).scalar() or 0
        stmt = stmt.order_by(
            Campaign.confidence.desc(), Campaign.created_at.desc()
        ).limit(limit)
        rows = list((await session.execute(stmt)).scalars())

        customer_names: dict[int, str] = {}
        for r in rows:
            if r.customer_id not in customer_names:
                c = await session.get(Customer, r.customer_id)
                customer_names[r.customer_id] = c.name if c else f"#{r.customer_id}"

        campaigns_out = [
            {
                "id": r.id,
                "customer": customer_names[r.customer_id],
                "status": r.status,
                "confidence": round(r.confidence, 3),
                "finding_count": r.finding_count,
                "asset_count": r.asset_count,
                "technique_ids": r.technique_ids or [],
                "tactic_ids": r.tactic_ids or [],
                "source_ids": r.source_ids or [],
                "severities": r.severities or {},
                "window_start": r.window_start.isoformat() if r.window_start else None,
                "window_end": r.window_end.isoformat() if r.window_end else None,
                "detection_reason": r.detection_reason,
            }
            for r in rows
        ]
        return {
            "total_count": total,
            "returned_count": len(campaigns_out),
            "campaigns": campaigns_out,
        }
