"""Return file paths for a report so Bot 2 can send attachments."""
from __future__ import annotations

from pathlib import Path

from ati_evn.agent.tools._action_base import register_action_tool
from ati_evn.agent.tools._base import tool_error
from ati_evn.db.models import Report
from ati_evn.db.session import async_session


@register_action_tool(
    name="download_report",
    destructive=False,
    description=(
        "Get file paths for a report. Returns html_path and pdf_path "
        "which Bot 2 can attach to Telegram. Analyst can also run "
        "/download_report <id> directly."
    ),
    parameters={
        "type": "object",
        "properties": {"report_id": {"type": "integer"}},
        "required": ["report_id"],
    },
)
async def download_report(report_id: int) -> dict:
    async with async_session() as session:
        r = await session.get(Report, report_id)
        if not r:
            return tool_error(f"Report #{report_id} not found")

    html_exists = bool(r.html_path) and Path(r.html_path).exists()
    pdf_exists = bool(r.pdf_path) and Path(r.pdf_path).exists()

    return {
        "report_id": r.id,
        "type": r.report_type,
        "html_path": r.html_path if html_exists else None,
        "pdf_path": r.pdf_path if pdf_exists else None,
        "html_available": html_exists,
        "pdf_available": pdf_exists,
        "download_command_hint": f"/download_report {r.id}",
    }
