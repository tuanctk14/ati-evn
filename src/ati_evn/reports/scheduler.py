"""Weekly global report scheduler -- Monday 06:00 UTC."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from ati_evn.reports.generator import generate_global_report

logger = logging.getLogger("ati_evn.reports.scheduler")


async def run_weekly_global_report() -> dict:
    """Generate global report for the past 7 days. On failure: log + skip."""
    now = datetime.now(timezone.utc)
    from_dt = now - timedelta(days=7)

    logger.info("Weekly global report starting: %s -> %s", from_dt, now)

    try:
        result = await generate_global_report(
            from_dt=from_dt, to_dt=now,
            formats=["html", "pdf"],
            generated_by="scheduler",
        )
        logger.info(
            "Weekly report generated: id=%d, findings=%d, html=%s, pdf=%s",
            result["report_id"],
            result["data"]["findings"]["total"],
            result["files"].get("html_path"),
            result["files"].get("pdf_path"),
        )
        return {
            "success": True,
            "report_id": result["report_id"],
            "findings_total": result["data"]["findings"]["total"],
        }
    except Exception as e:
        logger.exception("Weekly report failed: %s", e)
        return {"success": False, "error": str(e)[:500]}
