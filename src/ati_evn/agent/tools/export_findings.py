"""Export findings to CSV via agent.

Schema note: Finding.first_seen (not created_at) is the timeline column;
uses is_test_finding (hotfix 8B.1's broader detector), not the older
is_test_scenario metadata-only check, to keep legacy test data out of
exports the same way it's kept out of reports.
"""
from __future__ import annotations

import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import select

from ati_evn.agent.tools._action_base import pending_confirmation, register_action_tool
from ati_evn.agent.tools._base import tool_error
from ati_evn.db.models import Customer, Finding, Severity
from ati_evn.db.query_utils import cve_only_filter
from ati_evn.db.query_utils_test import is_test_finding
from ati_evn.db.session import async_session

_SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


@register_action_tool(
    name="export_findings",
    destructive=True,
    description=(
        "Export findings to a CSV file. Filter by customer, minimum "
        "severity, date range. File saved under reports/exports/."
    ),
    parameters={
        "type": "object",
        "properties": {
            "customer": {"type": "string"},
            "min_severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
            "since_days": {"type": "integer", "default": 30},
            "limit": {"type": "integer", "default": 500},
        },
        "required": [],
    },
)
async def export_findings(
    customer: str | None = None, min_severity: str | None = None,
    since_days: int = 30, limit: int = 500, confirmed: bool = False,
) -> dict:
    if not confirmed:
        return pending_confirmation({
            "action": "export_findings",
            "customer": customer or "all",
            "min_severity": min_severity or "all",
            "since_days": since_days,
            "limit": limit,
            "note": "Will save CSV to reports/exports/",
        })

    cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)
    limit = min(max(limit, 1), 5000)

    async with async_session() as session:
        stmt = select(Finding).where(
            cve_only_filter(), Finding.first_seen >= cutoff,
        ).order_by(
            Finding.severity, Finding.first_seen.desc(),
        )

        if customer:
            from ati_evn.db.query_utils import customer_name_or_code_match
            cr = await session.execute(
                select(Customer.id).where(customer_name_or_code_match(customer)).limit(1)
            )
            cid = cr.scalar_one_or_none()
            if not cid:
                return tool_error(f"Customer '{customer}' not found")
            stmt = stmt.where(Finding.customer_id == cid)

        if min_severity:
            min_idx = _SEVERITY_ORDER.index(min_severity)
            allowed_enums = [Severity[s] for s in _SEVERITY_ORDER[min_idx:]]
            stmt = stmt.where(Finding.severity.in_(allowed_enums))

        all_findings = list((await session.execute(stmt)).scalars())
        all_findings = [f for f in all_findings if not is_test_finding(f)]
        all_findings = all_findings[:limit]

        cust_ids = {f.customer_id for f in all_findings if f.customer_id}
        cust_names = {}
        for cid in cust_ids:
            c = await session.get(Customer, cid)
            cust_names[cid] = c.name if c else None

    export_dir = Path("reports/exports")
    export_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    fname = export_dir / f"findings_{ts}.csv"

    with open(fname, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "severity", "title", "customer", "ioc_type", "ioc_value", "sources", "status", "first_seen", "matched_asset"])
        for fi in all_findings:
            w.writerow([
                fi.id,
                fi.severity.value if hasattr(fi.severity, "value") else str(fi.severity),
                fi.title,
                cust_names.get(fi.customer_id) or "-",
                fi.ioc_type,
                fi.ioc_value,
                ",".join(fi.sources or []),
                fi.status.value if hasattr(fi.status, "value") else str(fi.status),
                fi.first_seen.isoformat() if fi.first_seen else "",
                fi.matched_asset or "",
            ])

    return {
        "status": "exported",
        "file_path": str(fname),
        "count": len(all_findings),
        "size_bytes": fname.stat().st_size,
    }
