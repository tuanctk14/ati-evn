"""Trigger CyRadar-style HTML+PDF report generation via agent.

Distinct from the existing `generate_report` tool (slice 5B.2 markdown
export, read-only, ~1s, no confirmation) -- this tool wraps slice 8A/8B's
generate_global_report / generate_customer_report: produces HTML+PDF
files with an LLM narrative, takes 10-30s, and is destructive (writes a
Report row + files to disk), so it requires confirmation.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from ati_evn.agent.tools._action_base import pending_confirmation, register_action_tool
from ati_evn.agent.tools._base import tool_error
from ati_evn.db.models import Customer
from ati_evn.db.query_utils import customer_name_or_code_match
from ati_evn.db.session import async_session


@register_action_tool(
    name="trigger_report_generation",
    destructive=True,
    description=(
        "Generate a CyRadar-style CTI report as HTML+PDF FILES (not inline "
        "text) -- 8 sections, LLM 3-paragraph Executive Summary, ~10-30s. "
        "Global scope or per-customer. Use this when the analyst wants a "
        "downloadable report file, not a quick inline summary (for that, "
        "use the 'generate_report' tool instead, which returns markdown "
        "text immediately with no file and no confirmation)."
    ),
    parameters={
        "type": "object",
        "properties": {
            "customer": {
                "type": "string",
                "description": "Customer name/short_code. Omit for global.",
            },
            "window": {
                "type": "string",
                "description": "Time window: '7d', '24h', '30d'. Ignored if from_date/to_date given.",
            },
            "from_date": {"type": "string", "description": "ISO date YYYY-MM-DD (inclusive start)"},
            "to_date": {"type": "string", "description": "ISO date YYYY-MM-DD (exclusive end)"},
            "format": {"type": "string", "enum": ["html", "pdf", "both"], "default": "both"},
        },
        "required": [],
    },
)
async def trigger_report_generation(
    customer: str | None = None,
    window: str | None = None,
    from_date: str | None = None,
    to_date: str | None = None,
    format: str = "both",
    confirmed: bool = False,
) -> dict:
    now = datetime.now(timezone.utc)
    try:
        if from_date and to_date:
            from_dt = datetime.fromisoformat(from_date).replace(tzinfo=timezone.utc)
            to_dt = datetime.fromisoformat(to_date).replace(tzinfo=timezone.utc)
        elif window:
            if window.endswith("d"):
                from_dt = now - timedelta(days=int(window[:-1]))
            elif window.endswith("h"):
                from_dt = now - timedelta(hours=int(window[:-1]))
            else:
                return tool_error(f"Invalid window: {window}")
            to_dt = now
        else:
            from_dt = now - timedelta(days=7)
            to_dt = now
    except ValueError as e:
        return tool_error(f"Date parse error: {e}")

    customer_id = None
    customer_display = "global"
    if customer:
        async with async_session() as session:
            row = await session.execute(
                select(Customer.id, Customer.name).where(
                    customer_name_or_code_match(customer),
                    Customer.deleted_at.is_(None),
                ).limit(1)
            )
            r = row.first()
            if not r:
                return tool_error(f"Customer '{customer}' not found")
            customer_id = r.id
            customer_display = r.name

    if not confirmed:
        return pending_confirmation({
            "action": "trigger_report_generation",
            "scope": customer_display,
            "window": f"{from_dt.date()} → {to_dt.date()}",
            "format": format,
            "estimated_time": "10-30s (LLM narrative)",
        })

    from ati_evn.reports.generator import generate_customer_report, generate_global_report

    formats = ["html", "pdf"] if format == "both" else [format]

    if customer_id:
        result = await generate_customer_report(
            customer_id, from_dt, to_dt, formats, generated_by="agent",
        )
    else:
        result = await generate_global_report(
            from_dt, to_dt, formats, generated_by="agent",
        )

    return {
        "status": "generated",
        "report_id": result["report_id"],
        "scope": customer_display,
        "window": f"{from_dt.date()} → {to_dt.date()}",
        "findings_total": result["data"]["findings"]["total"],
        "html_path": result["files"].get("html_path"),
        "pdf_path": result["files"].get("pdf_path"),
        "html_size_bytes": result["files"].get("html_size_bytes"),
        "pdf_size_bytes": result["files"].get("pdf_size_bytes"),
    }
