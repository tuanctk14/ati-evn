"""get_brand_abuse_detail -- full detail of one brand abuse sighting + findings."""
from __future__ import annotations

from sqlalchemy import select

from ati_evn.agent.tools._base import register_tool, tool_error
from ati_evn.db.models import BrandAbuseSighting, Customer, Finding
from ati_evn.db.session import async_session


@register_tool(
    name="get_brand_abuse_detail",
    description="Full detail of one urlscan.io brand abuse sighting by ID, including derived findings.",
    parameters={
        "type": "object",
        "properties": {"sighting_id": {"type": "integer"}},
        "required": ["sighting_id"],
    },
)
async def get_brand_abuse_detail(sighting_id: int) -> dict:
    async with async_session() as session:
        sighting = await session.get(BrandAbuseSighting, sighting_id)
        if not sighting:
            return tool_error(f"Sighting #{sighting_id} not found")

        # Finding.metadata_ is a plain JSON column (not JSONB), so it can't
        # be filtered with a SQL-level ->>/astext operator -- load
        # candidates and check metadata_ in Python (same pattern as
        # exposure_rules/finding_creator.py's dedup check, slice 9B).
        rows = await session.execute(select(Finding))
        findings = [
            f for f in rows.scalars()
            if (f.metadata_ or {}).get("brand_abuse_id") == sighting_id
        ]

        customer_name = None
        if sighting.customer_id:
            c = await session.get(Customer, sighting.customer_id)
            if c:
                customer_name = c.name

        return {
            "sighting": {
                "id": sighting.id, "url": sighting.url, "domain": sighting.domain,
                "page_title": sighting.page_title,
                "keyword_matched": sighting.keyword_matched,
                "customer": customer_name,
                "rule_matched": sighting.rule_matched,
                "rule_severity": sighting.rule_severity,
                "verdict_malicious": sighting.verdict_malicious,
                "verdict_score": sighting.verdict_score,
                "engines_malicious_total": sighting.engines_malicious_total,
                "typosquat_distance": sighting.typosquat_distance,
                "llm_classified": sighting.llm_classified,
                "llm_relevant": sighting.llm_relevant,
                "llm_reasoning": sighting.llm_reasoning,
                "status": sighting.status,
                "first_seen_local": sighting.first_seen_local.isoformat() if sighting.first_seen_local else None,
                "last_seen_local": sighting.last_seen_local.isoformat() if sighting.last_seen_local else None,
            },
            "findings": [
                {
                    "id": f.id, "title": f.title,
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    "status": f.status.value if hasattr(f.status, "value") else str(f.status),
                }
                for f in findings
            ],
        }
