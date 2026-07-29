"""search_indicators — filtered list of ThreatIndicators (non-CVE signals)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import desc, select

from ati_evn.agent.tools._action_base import register_action_tool
from ati_evn.agent.tools._base import tool_error
from ati_evn.db.models import Customer, ThreatIndicator
from ati_evn.db.query_utils import customer_name_or_code_match, ti_default_status_filter
from ati_evn.db.session import async_session

VALID_TYPES = [
    "ipv4", "ipv6", "domain", "url", "sha256", "sha1", "md5",
    "brand_abuse", "exposed_document", "exposure",
]


@register_action_tool(
    name="search_indicators",
    destructive=False,
    description=(
        "Search ThreatIndicators (non-CVE ephemeral signals: IOC, brand "
        "abuse, doc leak, exposure). Filter by type, customer, severity, "
        "status, time window. Read-only -- use acknowledge_indicator / "
        "add_indicator_note to modify."
    ),
    parameters={
        "type": "object",
        "properties": {
            "indicator_type": {"type": "string", "enum": VALID_TYPES},
            "customer": {"type": "string"},
            "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
            "status": {
                "type": "string",
                "enum": ["active", "acknowledged", "stale", "archived"],
                "description": (
                    "Omit for the default view (active + acknowledged, "
                    "excludes stale/archived). Pass explicitly to see "
                    "only one status, e.g. 'stale' for expired indicators."
                ),
            },
            "keyword": {"type": "string", "description": "Match title or indicator_value"},
            "since_days": {"type": "integer", "default": 30},
            "limit": {"type": "integer", "default": 20},
        },
        "required": [],
    },
)
async def search_indicators(
    indicator_type: str | None = None,
    customer: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    keyword: str | None = None,
    since_days: int = 30,
    limit: int = 20,
) -> dict:
    limit = min(max(limit, 1), 100)
    cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)

    async with async_session() as session:
        stmt = select(ThreatIndicator).where(
            ThreatIndicator.first_seen >= cutoff,
        ).order_by(desc(ThreatIndicator.first_seen)).limit(limit)

        if status:
            stmt = stmt.where(ThreatIndicator.status == status)
        else:
            stmt = stmt.where(ti_default_status_filter())

        if indicator_type:
            stmt = stmt.where(ThreatIndicator.indicator_type == indicator_type)
        if severity:
            stmt = stmt.where(ThreatIndicator.severity == severity.upper())
        if keyword:
            pattern = f"%{keyword}%"
            stmt = stmt.where(
                (ThreatIndicator.title.ilike(pattern))
                | (ThreatIndicator.indicator_value.ilike(pattern))
            )

        if customer:
            cr = await session.execute(
                select(Customer.id).where(customer_name_or_code_match(customer)).limit(1)
            )
            cid = cr.scalar_one_or_none()
            if not cid:
                return tool_error(f"Customer '{customer}' not found")
            stmt = stmt.where(ThreatIndicator.customer_id == cid)

        rows = list((await session.execute(stmt)).scalars())

        customer_names: dict[int, str | None] = {}
        for ti in rows:
            if ti.customer_id not in customer_names:
                c = await session.get(Customer, ti.customer_id)
                customer_names[ti.customer_id] = c.name if c else None

    return {
        "count": len(rows),
        "indicators": [
            {
                "id": ti.id,
                "type": ti.indicator_type,
                "value": ti.indicator_value[:200],
                "title": ti.title[:200],
                "severity": ti.severity.value if hasattr(ti.severity, "value") else str(ti.severity),
                "customer": customer_names.get(ti.customer_id),
                "status": ti.status,
                "source": ti.source,
                "sources": ti.sources or [],
                "first_seen": ti.first_seen.isoformat() if ti.first_seen else None,
                "acknowledged": bool(ti.acknowledged_at),
                "expires_at": ti.expires_at.isoformat() if ti.expires_at else None,
            }
            for ti in rows
        ],
    }
