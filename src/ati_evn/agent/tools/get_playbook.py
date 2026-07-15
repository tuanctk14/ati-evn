"""get_playbook — read-only playbook_cache lookup. Never triggers LLM generation."""
from __future__ import annotations

from sqlalchemy import select

from ati_evn.agent.tools._base import register_tool, tool_error
from ati_evn.db.models import CustomerAsset, Finding, PlaybookCache
from ati_evn.db.session import async_session


@register_tool(
    name="get_playbook",
    description=(
        "Look up a cached NIST 800-61 playbook by CVE-ID or finding_id. "
        "Exactly one of cve_id/finding_id is required. Does NOT generate a "
        "new playbook — if not cached, tells the user to run /playbook."
    ),
    parameters={
        "type": "object",
        "properties": {
            "cve_id": {"type": "string", "description": "CVE-ID"},
            "finding_id": {"type": "integer", "description": "Finding ID (resolved to CVE + network segment)"},
        },
        "required": [],
    },
)
async def get_playbook(cve_id: str | None = None, finding_id: int | None = None) -> dict:
    if not cve_id and not finding_id:
        return tool_error("Exactly one of cve_id or finding_id is required.")
    if cve_id and finding_id:
        return tool_error("Provide only one of cve_id or finding_id, not both.")

    async with async_session() as session:
        network_segment = None

        if finding_id:
            finding = await session.get(Finding, finding_id)
            if not finding:
                return tool_error(f"Finding #{finding_id} not found", hint="Try search_findings first.")
            if finding.ioc_type != "cve_id":
                return tool_error(f"Finding #{finding_id} is not a CVE finding.")
            cve_id = finding.ioc_value.upper()
            if finding.matched_asset:
                asset_row = await session.execute(
                    select(CustomerAsset).where(
                        CustomerAsset.customer_id == finding.customer_id,
                        CustomerAsset.asset_value == finding.matched_asset,
                    ).limit(1)
                )
                asset = asset_row.scalar_one_or_none()
                if asset and asset.network_segment:
                    network_segment = asset.network_segment.value

        cve_id = cve_id.upper()
        cached_row = await session.execute(
            select(PlaybookCache).where(
                PlaybookCache.cve_id == cve_id,
                PlaybookCache.network_segment == network_segment,
            )
        )
        cached = cached_row.scalar_one_or_none()

        if not cached:
            return {
                "markdown": "",
                "note": f"Not cached. Use /playbook {cve_id} command to generate first.",
            }

        return {
            "markdown": cached.playbook_md,
            "cve_id": cve_id,
            "network_segment": network_segment,
            "reused_count": cached.reused_count,
            "generated_at": cached.generated_at.isoformat() if cached.generated_at else None,
        }
