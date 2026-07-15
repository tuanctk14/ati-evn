"""get_customer_summary — deterministic customer snapshot (no LLM)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from ati_evn.agent.tools._base import register_tool, tool_error
from ati_evn.db.models import AlertQueue, Customer, CustomerAsset, Finding, FindingStatus
from ati_evn.db.query_utils import customer_name_or_code_match, only_live_asset
from ati_evn.db.session import async_session


async def _resolve_customer(session, query_str: str) -> Customer | None:
    if query_str.isdigit():
        return await session.get(Customer, int(query_str))
    result = await session.execute(select(Customer).where(customer_name_or_code_match(query_str)).limit(1))
    return result.scalar_one_or_none()


@register_tool(
    name="get_customer_summary",
    description="Deterministic snapshot of a customer: assets, findings, alerts, recent activity. No LLM.",
    parameters={
        "type": "object",
        "properties": {
            "customer": {"type": "string", "description": "Customer name or ID"},
        },
        "required": ["customer"],
    },
)
async def get_customer_summary(customer: str) -> dict:
    async with async_session() as session:
        cust = await _resolve_customer(session, customer)
        if not cust:
            return tool_error(f"Customer '{customer}' not found", hint="Check the name spelling or try /customer.")

        parent_name = None
        if cust.parent_id:
            parent = await session.get(Customer, cust.parent_id)
            parent_name = parent.name if parent else None

        asset_rows = await session.execute(
            select(CustomerAsset.asset_type, func.count()).where(
                CustomerAsset.customer_id == cust.id, only_live_asset(),
            ).group_by(CustomerAsset.asset_type)
        )
        asset_breakdown = {t.value: c for t, c in asset_rows.all()}

        ics_count = (await session.execute(
            select(func.count()).select_from(CustomerAsset).where(
                CustomerAsset.customer_id == cust.id, only_live_asset(),
                CustomerAsset.is_ics.is_(True),
            )
        )).scalar_one()

        open_rows = await session.execute(
            select(Finding.severity, func.count()).where(
                Finding.customer_id == cust.id, Finding.status == FindingStatus.OPEN,
            ).group_by(Finding.severity)
        )
        open_by_severity = {s.value: c for s, c in open_rows.all()}

        cutoff_30d = datetime.now(timezone.utc) - timedelta(days=30)
        closed_count = (await session.execute(
            select(func.count()).select_from(Finding).where(
                Finding.customer_id == cust.id, Finding.status == FindingStatus.CLOSED,
                Finding.closed_at >= cutoff_30d,
            )
        )).scalar_one()
        fp_count = (await session.execute(
            select(func.count()).select_from(Finding).where(
                Finding.customer_id == cust.id, Finding.status == FindingStatus.FALSE_POSITIVE,
                Finding.closed_at >= cutoff_30d,
            )
        )).scalar_one()

        cutoff_7d = datetime.now(timezone.utc) - timedelta(days=7)
        alert_rows = await session.execute(
            select(AlertQueue.state, func.count()).where(
                AlertQueue.customer_id == cust.id, AlertQueue.created_at >= cutoff_7d,
            ).group_by(AlertQueue.state)
        )
        alert_stats = dict(alert_rows.all())

        last_update = (await session.execute(
            select(func.max(Finding.last_seen)).where(Finding.customer_id == cust.id)
        )).scalar_one()

        return {
            "name": cust.name,
            "parent_name": parent_name,
            "industry": cust.industry,
            "tier": cust.tier,
            "primary_domain": cust.primary_domain,
            "active": cust.active,
            "asset_breakdown": asset_breakdown,
            "ics_asset_count": ics_count,
            "open_findings_by_severity": open_by_severity,
            "closed_last_30d": closed_count,
            "false_positive_last_30d": fp_count,
            "alert_stats_last_7d": alert_stats,
            "last_activity": last_update.isoformat() if last_update else None,
        }
