"""Export ThreatIndicators to CSV via agent, same pattern as export_findings."""
from __future__ import annotations

import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import select

from ati_evn.agent.tools._action_base import pending_confirmation, register_action_tool
from ati_evn.agent.tools._base import tool_error
from ati_evn.db.models import Customer, Severity, ThreatIndicator
from ati_evn.db.query_utils import customer_name_or_code_match
from ati_evn.db.session import async_session

_SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


@register_action_tool(
    name="export_indicators",
    destructive=True,
    description=(
        "Export ThreatIndicators to a CSV file. Filter by customer, type, "
        "minimum severity, date range. File saved under reports/exports/."
    ),
    parameters={
        "type": "object",
        "properties": {
            "customer": {"type": "string"},
            "indicator_type": {
                "type": "string",
                "enum": [
                    "ipv4", "ipv6", "domain", "url", "sha256", "sha1", "md5",
                    "brand_abuse", "exposed_document", "exposure",
                ],
            },
            "min_severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
            "since_days": {"type": "integer", "default": 30},
            "limit": {"type": "integer", "default": 500},
        },
        "required": [],
    },
)
async def export_indicators(
    customer: str | None = None,
    indicator_type: str | None = None,
    min_severity: str | None = None,
    since_days: int = 30,
    limit: int = 500,
    confirmed: bool = False,
) -> dict:
    if not confirmed:
        return pending_confirmation({
            "action": "export_indicators",
            "customer": customer or "all",
            "indicator_type": indicator_type or "all",
            "min_severity": min_severity or "all",
            "since_days": since_days,
            "limit": limit,
            "note": "Will save CSV to reports/exports/",
        })

    cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)
    limit = min(max(limit, 1), 5000)

    async with async_session() as session:
        stmt = select(ThreatIndicator).where(
            ThreatIndicator.first_seen >= cutoff,
        ).order_by(ThreatIndicator.severity, ThreatIndicator.first_seen.desc())

        if customer:
            cr = await session.execute(
                select(Customer.id).where(customer_name_or_code_match(customer)).limit(1)
            )
            cid = cr.scalar_one_or_none()
            if not cid:
                return tool_error(f"Customer '{customer}' not found")
            stmt = stmt.where(ThreatIndicator.customer_id == cid)

        if indicator_type:
            stmt = stmt.where(ThreatIndicator.indicator_type == indicator_type)

        if min_severity:
            min_idx = _SEVERITY_ORDER.index(min_severity)
            allowed_enums = [Severity[s] for s in _SEVERITY_ORDER[min_idx:]]
            stmt = stmt.where(ThreatIndicator.severity.in_(allowed_enums))

        all_tis = list((await session.execute(stmt)).scalars())[:limit]

        cust_ids = {ti.customer_id for ti in all_tis if ti.customer_id}
        cust_names = {}
        for cid in cust_ids:
            c = await session.get(Customer, cid)
            cust_names[cid] = c.name if c else None

    export_dir = Path("reports/exports")
    export_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    fname = export_dir / f"indicators_{ts}.csv"

    with open(fname, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "id", "indicator_type", "indicator_value", "severity", "customer",
            "status", "source", "title", "first_seen", "expires_at", "acknowledged",
        ])
        for ti in all_tis:
            w.writerow([
                ti.id,
                ti.indicator_type,
                ti.indicator_value,
                ti.severity.value if hasattr(ti.severity, "value") else str(ti.severity),
                cust_names.get(ti.customer_id) or "-",
                ti.status,
                ti.source,
                ti.title,
                ti.first_seen.isoformat() if ti.first_seen else "",
                ti.expires_at.isoformat() if ti.expires_at else "",
                "yes" if ti.acknowledged_at else "no",
            ])

    return {
        "status": "exported",
        "file_path": str(fname),
        "count": len(all_tis),
        "size_bytes": fname.stat().st_size,
    }
