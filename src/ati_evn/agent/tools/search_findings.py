"""search_findings — filtered list of Findings, structured (no VN formatting)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from ati_evn.agent.tools._base import register_tool
from ati_evn.db.models import Customer, Finding
from ati_evn.db.query_utils import cve_only_filter, customer_name_or_code_match, only_live_customer
from ati_evn.db.session import async_session

HARD_CAP = 20


@register_tool(
    name="search_findings",
    description=(
        "Search Findings with optional filters: customer name, severity, "
        "since_days (age window), ioc_type, status. Returns up to 20 rows, "
        "sorted by severity then recency."
    ),
    parameters={
        "type": "object",
        "properties": {
            "customer": {"type": "string", "description": "Customer name (partial match)"},
            "severity": {"type": "string", "description": "CRITICAL|HIGH|MEDIUM|LOW|INFO"},
            "since_days": {"type": "integer", "description": "Only findings first_seen within this many days"},
            "ioc_type": {"type": "string", "description": "e.g. cve_id, ipv4, domain"},
            "status": {"type": "string", "description": "open|acknowledged|closed|false_positive|expired"},
            "limit": {"type": "integer", "description": "Max rows to return (capped at 20)", "default": 20},
        },
        "required": [],
    },
)
async def search_findings(
    customer: str | None = None,
    severity: str | None = None,
    since_days: int | None = None,
    ioc_type: str | None = None,
    status: str | None = None,
    limit: int = 20,
) -> dict:
    limit = min(limit or 20, HARD_CAP)

    async with async_session() as session:
        stmt = select(Finding, Customer.name).join(
            Customer, Customer.id == Finding.customer_id,
        ).where(only_live_customer(), cve_only_filter())

        if customer:
            stmt = stmt.where(customer_name_or_code_match(customer))
        if severity:
            stmt = stmt.where(Finding.severity == severity.upper())
        if since_days:
            cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)
            stmt = stmt.where(Finding.first_seen >= cutoff)
        if ioc_type:
            stmt = stmt.where(Finding.ioc_type == ioc_type)
        if status:
            stmt = stmt.where(Finding.status == status.lower())

        count_stmt = select(func.count()).select_from(stmt.subquery())
        total_count = (await session.execute(count_stmt)).scalar_one()

        stmt = stmt.order_by(Finding.severity.desc(), Finding.first_seen.desc()).limit(limit)
        rows = (await session.execute(stmt)).all()

    findings = [
        {
            "id": f.id,
            "ioc_type": f.ioc_type,
            "ioc_value": f.ioc_value,
            "severity": f.severity.value,
            "customer_name": name,
            "matched_asset": f.matched_asset,
            "first_seen": f.first_seen.isoformat(),
            "status": f.status.value,
            "source_count": f.source_count,
            "sources": f.sources or [],
        }
        for f, name in rows
    ]

    return {
        "total_count": total_count,
        "returned_count": len(findings),
        "findings": findings,
    }
