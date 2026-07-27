"""Query the Report table (slice 8B) via agent -- non-destructive."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import desc, select

from ati_evn.agent.tools._action_base import register_action_tool
from ati_evn.db.models import Customer, Report
from ati_evn.db.session import async_session


@register_action_tool(
    name="list_reports",
    destructive=False,
    description="List recently generated reports. Filter by type (global/customer) or customer name.",
    parameters={
        "type": "object",
        "properties": {
            "report_type": {"type": "string", "enum": ["global", "customer"]},
            "customer": {"type": "string"},
            "since_days": {"type": "integer", "default": 30},
            "limit": {"type": "integer", "default": 20},
        },
        "required": [],
    },
)
async def list_reports(
    report_type: str | None = None, customer: str | None = None,
    since_days: int = 30, limit: int = 20,
) -> dict:
    limit = min(max(limit, 1), 50)
    cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)

    async with async_session() as session:
        stmt = select(Report).where(Report.generated_at >= cutoff).order_by(desc(Report.generated_at)).limit(limit)
        if report_type:
            stmt = stmt.where(Report.report_type == report_type)

        if customer:
            from ati_evn.db.query_utils import customer_name_or_code_match
            cust_r = await session.execute(
                select(Customer.id).where(customer_name_or_code_match(customer)).limit(1)
            )
            cid = cust_r.scalar_one_or_none()
            if cid:
                stmt = stmt.where(Report.customer_id == cid)

        rows = list((await session.execute(stmt)).scalars())

        customer_names = {}
        for r in rows:
            if r.customer_id and r.customer_id not in customer_names:
                c = await session.get(Customer, r.customer_id)
                customer_names[r.customer_id] = c.name if c else None

    return {
        "count": len(rows),
        "reports": [
            {
                "id": r.id,
                "type": r.report_type,
                "customer": customer_names.get(r.customer_id) if r.customer_id else "GLOBAL",
                "window": f"{r.window_from.date()} → {r.window_to.date()}",
                "findings_total": r.findings_total,
                "html_size_kb": (r.html_size_bytes or 0) // 1024,
                "pdf_size_kb": (r.pdf_size_bytes or 0) // 1024,
                "generated_at": r.generated_at.isoformat() if r.generated_at else None,
                "generated_by": r.generated_by,
            }
            for r in rows
        ],
    }
