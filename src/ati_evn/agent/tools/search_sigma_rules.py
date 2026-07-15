"""search_sigma_rules — community Sigma rules matching a CVE or ATT&CK technique."""
from __future__ import annotations

from sqlalchemy import select

from ati_evn.agent.tools._base import register_tool, tool_error
from ati_evn.db.models import SigmaRule
from ati_evn.db.session import async_session

HARD_CAP = 10
SIGMA_GITHUB_BLOB_BASE = "github.com/SigmaHQ/sigma/blob/master/"


def _rule_dict(r: SigmaRule) -> dict:
    return {
        "rule_uuid": r.rule_uuid,
        "title": r.title,
        "level": r.level,
        "status": r.status,
        "source_path": f"{SIGMA_GITHUB_BLOB_BASE}{r.source_path}",
        "cve_refs": r.cve_refs or [],
        "attack_techniques": r.attack_techniques or [],
    }


@register_tool(
    name="search_sigma_rules",
    description="Search community Sigma rules by CVE-ID or ATT&CK technique. At least one filter required.",
    parameters={
        "type": "object",
        "properties": {
            "cve_id": {"type": "string", "description": "CVE-ID, e.g. CVE-2024-1709"},
            "attack_technique": {"type": "string", "description": "ATT&CK technique ID, e.g. T1190"},
        },
        "required": [],
    },
)
async def search_sigma_rules(cve_id: str | None = None, attack_technique: str | None = None) -> dict:
    if not cve_id and not attack_technique:
        return tool_error("At least one of cve_id or attack_technique is required.")

    async with async_session() as session:
        rules: list[SigmaRule] = []
        if cve_id:
            rows = await session.execute(
                select(SigmaRule).where(SigmaRule.cve_refs.contains([cve_id.upper()])).limit(HARD_CAP)
            )
            rules = list(rows.scalars())

        if not rules and attack_technique:
            rows = await session.execute(
                select(SigmaRule).where(
                    SigmaRule.attack_techniques.contains([attack_technique.upper()])
                ).limit(HARD_CAP)
            )
            rules = list(rows.scalars())

        total_count = len(rules)
        rule_list = [_rule_dict(r) for r in rules[:HARD_CAP]]

    return {
        "total_count": total_count,
        "returned_count": len(rule_list),
        "rules": rule_list,
    }
