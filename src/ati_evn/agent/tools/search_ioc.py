"""search_ioc — look up a non-CVE IOC (IP/domain/hash) across feeds."""
from __future__ import annotations

from sqlalchemy import select

from ati_evn.agent.tools._base import register_tool, tool_error
from ati_evn.db.models import Detection, Finding
from ati_evn.db.session import async_session


@register_tool(
    name="search_ioc",
    description="Look up a non-CVE IOC (IP, domain, hash) — feed sources, first/last seen, related findings.",
    parameters={
        "type": "object",
        "properties": {
            "value": {"type": "string", "description": "IOC value, e.g. an IP, domain, or file hash"},
        },
        "required": ["value"],
    },
)
async def search_ioc(value: str) -> dict:
    value_norm = value.strip().lower()
    async with async_session() as session:
        det_rows = await session.execute(
            select(Detection).where(
                Detection.ioc_value == value_norm,
                Detection.ioc_type != "cve_id",
            )
        )
        detections = list(det_rows.scalars())
        if not detections:
            return tool_error(
                f"IOC '{value}' not found",
                hint="Check the value is correct, or try search_findings/search_cve instead.",
            )

        ioc_type = detections[0].ioc_type
        feeds = sorted({d.source for d in detections})
        first_seen = min(d.first_seen for d in detections)
        last_seen = max(d.last_seen for d in detections)
        severity = max(
            detections, key=lambda d: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(d.severity.value, 0),
        ).severity.value

        finding_rows = await session.execute(
            select(Finding.id).where(
                Finding.ioc_type == ioc_type, Finding.ioc_value == value_norm,
            )
        )
        finding_ids = [r[0] for r in finding_rows.all()]

        return {
            "ioc_type": ioc_type,
            "ioc_value": value_norm,
            "feeds": feeds,
            "first_seen": first_seen.isoformat(),
            "last_seen": last_seen.isoformat(),
            "severity": severity,
            "related_finding_ids": finding_ids,
            "related_finding_count": len(finding_ids),
        }
