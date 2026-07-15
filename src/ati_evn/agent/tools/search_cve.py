"""search_cve — exact CVE-ID lookup or keyword search over CVE descriptions."""
from __future__ import annotations

import re

from sqlalchemy import select

from ati_evn.agent.tools._base import register_tool
from ati_evn.db.models import CveCweMap, CveProductMap, Detection, Finding
from ati_evn.db.session import async_session

HARD_CAP = 20
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


async def _build_cve_entry(session, cve_id: str) -> dict:
    cve_upper = cve_id.upper()
    cve_lower = cve_id.lower()

    det_row = await session.execute(
        select(Detection.raw_text, Detection.metadata_).where(
            Detection.ioc_value == cve_lower,
            Detection.source == "nvd",
        ).limit(1)
    )
    row = det_row.first()
    description = (row[0] if row else None) or ""
    meta = (row[1] if row else None) or {}
    cvss = meta.get("cvss_score")

    cwe_rows = await session.execute(
        select(CveCweMap.cwe_id).where(CveCweMap.cve_id == cve_upper)
    )
    cwe_ids = sorted({r[0] for r in cwe_rows})

    prod_rows = await session.execute(
        select(CveProductMap).where(CveProductMap.cve_id == cve_upper)
        .order_by(CveProductMap.confidence.desc()).limit(5)
    )
    product_map = [
        {"vendor": p.vendor, "product": p.product, "version_range": p.version_range}
        for p in prod_rows.scalars()
    ]

    finding_rows = await session.execute(
        select(Finding.id).where(
            Finding.ioc_type == "cve_id", Finding.ioc_value == cve_lower,
        )
    )
    finding_ids = [r[0] for r in finding_rows.all()]

    return {
        "cve_id": cve_upper,
        "description": description[:300],
        "cvss": cvss,
        "cwe_ids": cwe_ids,
        "has_finding": bool(finding_ids),
        "finding_ids": finding_ids,
        "product_map": product_map,
    }


@register_tool(
    name="search_cve",
    description=(
        "Look up a CVE by exact ID (CVE-YYYY-NNNNN) or search by keyword in "
        "CVE descriptions (e.g. vendor name)."
    ),
    parameters={
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "CVE-ID or keyword"},
        },
        "required": ["query"],
    },
)
async def search_cve(query: str) -> dict:
    query = query.strip()
    async with async_session() as session:
        if CVE_PATTERN.match(query):
            entry = await _build_cve_entry(session, query)
            return {"total_count": 1, "returned_count": 1, "cves": [entry]}

        det_rows = await session.execute(
            select(Detection.ioc_value).where(
                Detection.ioc_type == "cve_id",
                Detection.source == "nvd",
                Detection.raw_text.ilike(f"%{query}%"),
            ).distinct()
        )
        cve_values = [r[0] for r in det_rows.all()]
        total_count = len(cve_values)
        cves = []
        for cve_value in cve_values[:HARD_CAP]:
            cves.append(await _build_cve_entry(session, cve_value))

        return {
            "total_count": total_count,
            "returned_count": len(cves),
            "cves": cves,
        }
