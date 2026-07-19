"""get_exposure_detail — full detail of one exposure + derived findings."""
from __future__ import annotations

from sqlalchemy import select

from ati_evn.agent.tools._base import register_tool, tool_error
from ati_evn.db.models import Customer, Exposure, Finding
from ati_evn.db.session import async_session


@register_tool(
    name="get_exposure_detail",
    description="Full detail of one exposure by ID, including matched rule findings.",
    parameters={
        "type": "object",
        "properties": {"exposure_id": {"type": "integer"}},
        "required": ["exposure_id"],
    },
)
async def get_exposure_detail(exposure_id: int) -> dict:
    async with async_session() as session:
        exp = await session.get(Exposure, exposure_id)
        if not exp:
            return tool_error(f"Exposure #{exposure_id} not found")

        # Finding.metadata_ is a plain JSON column (not JSONB), so it can't
        # be filtered with a SQL-level `->>`/astext operator — load
        # candidates and check metadata_ in Python instead (same pattern
        # used by exposure_rules/finding_creator.py's dedup check).
        rows = await session.execute(select(Finding))
        findings = [
            f for f in rows.scalars()
            if (f.metadata_ or {}).get("exposure_id") == exposure_id
        ]

        customer_name = None
        if exp.customer_id:
            cust = await session.get(Customer, exp.customer_id)
            if cust:
                customer_name = cust.name

        return {
            "exposure": {
                "id": exp.id, "ip": exp.ip, "port": exp.port,
                "service_name": exp.service_name, "transport": exp.transport,
                "product": exp.product, "version": exp.version, "vendor": exp.vendor,
                "banner": (exp.banner or "")[:500],
                "tls_enabled": exp.tls_enabled, "tls_version": exp.tls_version,
                "tls_expired": exp.tls_expired, "tls_self_signed": exp.tls_self_signed,
                "auth_required": exp.auth_required,
                "capabilities": exp.capabilities or {},
                "asn": exp.asn, "asn_organization": exp.asn_organization,
                "country": exp.country,
                "asset_id": exp.asset_id, "customer": customer_name,
                "first_seen_censys": exp.first_seen_censys.isoformat() if exp.first_seen_censys else None,
                "first_seen_local": exp.first_seen_local.isoformat() if exp.first_seen_local else None,
                "last_seen_local": exp.last_seen_local.isoformat() if exp.last_seen_local else None,
                "status": exp.status,
            },
            "findings": [
                {
                    "id": f.id, "title": f.title,
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    "status": f.status.value if hasattr(f.status, "value") else str(f.status),
                    "rule_id": (f.metadata_ or {}).get("rule_id"),
                    "cve_id": (f.metadata_ or {}).get("cve_id"),
                    "sources": f.sources,
                }
                for f in findings
            ],
        }
