"""End-to-end orchestrators: gather -> narrative -> render -> files -> DB metadata."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from ati_evn.db.models import Report
from ati_evn.db.session import async_session
from ati_evn.reports.data_gatherer import gather_customer_report, gather_global_report
from ati_evn.reports.narrative import generate_customer_narrative, generate_narrative
from ati_evn.reports.renderer import generate_customer_report_files, generate_report_files

logger = logging.getLogger("ati_evn.reports.generator")


async def _persist_report_metadata(
    report_type: str, customer_id: int | None,
    from_dt: datetime, to_dt: datetime,
    files: dict, findings_total: int, generated_by: str,
) -> int:
    async with async_session() as session:
        report = Report(
            report_type=report_type,
            customer_id=customer_id,
            window_from=from_dt,
            window_to=to_dt,
            html_path=files.get("html_path"),
            pdf_path=files.get("pdf_path"),
            html_size_bytes=files.get("html_size_bytes") or 0,
            pdf_size_bytes=files.get("pdf_size_bytes") or 0,
            findings_total=findings_total,
            generated_at=datetime.now(timezone.utc),
            generated_by=generated_by,
            error_message="; ".join(files.get("errors") or []) or None,
        )
        session.add(report)
        await session.commit()
        await session.refresh(report)
        return report.id


async def generate_global_report(
    from_dt: datetime, to_dt: datetime,
    formats: list[str] | None = None,
    generated_by: str = "analyst",
) -> dict:
    """Full pipeline. Returns dict with report_id + paths + summary."""
    logger.info("Generating global report %s -> %s (formats=%s)", from_dt, to_dt, formats)

    data = await gather_global_report(from_dt, to_dt)
    logger.info(
        "Data gathered: %d findings, %d campaigns, %d exposures, "
        "%d doc leaks, %d brand sightings, %d malicious IPs",
        data["findings"]["total"],
        data["campaigns"]["total"],
        data["exposures"]["in_window"],
        data["document_leaks"]["in_window"],
        data["brand_abuse"]["in_window"],
        data["malicious_ips"]["total"],
    )

    narrative = await generate_narrative(data)
    logger.info("Narrative generated: %d chars", len(narrative))

    files = await generate_report_files(data, narrative, formats)
    logger.info("Files: %s", files)

    report_id = await _persist_report_metadata(
        "global", None, from_dt, to_dt, files, data["findings"]["total"], generated_by,
    )

    return {
        "report_id": report_id,
        "data": data,
        "narrative": narrative,
        "files": files,
    }


async def generate_customer_report(
    customer_id: int, from_dt: datetime, to_dt: datetime,
    formats: list[str] | None = None,
    generated_by: str = "analyst",
) -> dict:
    """Generate per-customer report. Persists metadata to the Report table."""
    logger.info(
        "Generating customer report customer_id=%d %s -> %s (formats=%s)",
        customer_id, from_dt, to_dt, formats,
    )

    data = await gather_customer_report(customer_id, from_dt, to_dt)
    short_code = data["meta"]["customer"]["short_code"] or f"cust{customer_id}"

    narrative = await generate_customer_narrative(data)
    logger.info("Customer narrative generated: %d chars", len(narrative))

    files = await generate_customer_report_files(data, narrative, short_code, formats)
    logger.info("Files: %s", files)

    report_id = await _persist_report_metadata(
        "customer", customer_id, from_dt, to_dt, files, data["findings"]["total"], generated_by,
    )

    return {
        "report_id": report_id,
        "data": data,
        "narrative": narrative,
        "files": files,
    }
