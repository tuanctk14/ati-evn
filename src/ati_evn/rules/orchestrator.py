"""Public API for the bot layer and CLI:

    async def get_rule_for_cve(cve_id, force_regen=False) -> dict

Returns:
    {
      "cve_id": "CVE-...",
      "source": "community" | "ai_generated",
      "community_count": 5,           # total community rules found
      "primary_rule": {
          "title": ..., "yaml": ..., "aql": ..., "source_ref": ...,
          "score": 130, "level": "high", "status": "stable",
          "reasoning": "stable | high | ATT&CK overlap: [T1190]",
      },
      "alternates": [...top 4 more scored...],  # only when community
      "ai_metadata": {...}  # only when AI generated
    }
"""
from __future__ import annotations

from sqlalchemy import select

from ati_evn.config import get_settings
from ati_evn.db.models import CveCweMap, CveProductMap, Detection, Finding
from ati_evn.db.session import async_session
from ati_evn.llm.client import LLMClient
from ati_evn.rules.aql_converter import sigma_yaml_to_aql
from ati_evn.rules.rule_matcher import ScoredRule, find_behavior_rules, find_community_rules
from ati_evn.rules.sigma_generator import generate_sigma_rule

SIGMA_GITHUB_BLOB_BASE = "github.com/SigmaHQ/sigma/blob/master/"

# How much to trust each match tier when no explicit AI confidence applies.
MATCH_CONFIDENCE = {
    "community_direct": 0.9,      # rule explicitly references this CVE
    "community_behavioral": 0.5,  # rule matches the attack pattern, may or
                                   # may not cover this specific CVE
}


async def _load_finding_context(session, cve_id: str) -> dict:
    """Fetch description, cvss, vendor/product/version_range, cwe_ids, and
    attack_context (techniques + kill_chain_phases) for a CVE.

    If no Finding exists yet for this CVE (detected but not matched to any
    customer asset), attack_context comes back empty — description/product
    data still populate from the CVE-level tables, which don't depend on
    customer matching.
    """
    cve_id_lower = cve_id.lower()

    # Description: prefer the NVD-source Detection's raw_text (same pattern
    # as enrichment/orchestrator.py's _enrich_cve).
    result = await session.execute(
        select(Detection.raw_text, Detection.metadata_).where(
            Detection.ioc_value == cve_id_lower,
            Detection.source == "nvd",
        ).limit(1)
    )
    row = result.first()
    description = (row[0] if row else None) or ""
    det_metadata = (row[1] if row else None) or {}
    cvss = det_metadata.get("cvss_score")

    # Vendor/product/version_range: prefer the highest-confidence row (NVD
    # over llm_inferred) when a CVE maps to multiple products.
    result = await session.execute(
        select(CveProductMap).where(CveProductMap.cve_id == cve_id.upper())
        .order_by(CveProductMap.confidence.desc())
        .limit(1)
    )
    cpm = result.scalar_one_or_none()
    vendor = cpm.vendor if cpm else None
    product = cpm.product if cpm else None
    version_range = cpm.version_range if cpm else None
    if cvss is None and cpm is not None:
        cvss = cpm.cvss_score

    # CWE ids
    result = await session.execute(
        select(CveCweMap.cwe_id).where(CveCweMap.cve_id == cve_id.upper())
    )
    cwe_ids = sorted({r[0] for r in result})

    # attack_context from any customer Finding for this CVE (JSON column —
    # metadata_ is a Python dict once loaded via the ORM, no raw SQL/JSONB
    # path needed here).
    result = await session.execute(
        select(Finding.metadata_).where(Finding.ioc_value == cve_id_lower).limit(1)
    )
    finding_row = result.first()
    finding_meta = (finding_row[0] if finding_row else None) or {}
    attack_context = finding_meta.get("attack_context") or {}
    attack_techniques = attack_context.get("techniques") or []
    kill_chain_phases = attack_context.get("kill_chain_phases") or []

    return {
        "description": description,
        "cvss": cvss,
        "vendor": vendor,
        "product": product,
        "version_range": version_range,
        "cwe_ids": cwe_ids,
        "attack_techniques": attack_techniques,
        "kill_chain_phases": kill_chain_phases,
    }


def _build_community_response(
    cve_id_upper: str, matches: list[ScoredRule], *, source: str,
) -> dict:
    primary = matches[0]
    yaml_text = primary.rule.raw_yaml
    return {
        "cve_id": cve_id_upper,
        "source": source,
        "match_confidence": MATCH_CONFIDENCE[source],
        "community_count": len(matches),
        "primary_rule": {
            "title": primary.rule.title,
            "yaml": yaml_text,
            "aql": sigma_yaml_to_aql(yaml_text),
            "source_ref": f"{SIGMA_GITHUB_BLOB_BASE}{primary.rule.source_path}",
            "score": primary.score,
            "level": primary.rule.level,
            "status": primary.rule.status,
            "reasoning": primary.reasoning,
        },
        "alternates": [
            {
                "title": s.rule.title,
                "source_ref": f"{SIGMA_GITHUB_BLOB_BASE}{s.rule.source_path}",
                "score": s.score,
                "reasoning": s.reasoning,
            }
            for s in matches[1:5]
        ],
    }


async def get_rule_for_cve(cve_id: str, *, force_regen: bool = False) -> dict:
    cve_id_upper = cve_id.upper().strip()
    async with async_session() as session:
        finding_ctx = await _load_finding_context(session, cve_id_upper)
        technique_ids = [t.get("id") for t in finding_ctx["attack_techniques"] if t.get("id")]

        if not force_regen:
            # Tier 1: direct CVE match — rule explicitly cites this CVE ID.
            community = await find_community_rules(session, cve_id_upper, technique_ids)
            if community:
                return _build_community_response(cve_id_upper, community, source="community_direct")

            # Tier 2: behavioral match by ATT&CK overlap — most SigmaHQ
            # rules aren't CVE-tagged at all (63/3142 are), so a CVE whose
            # finding has attack_context techniques but no direct rule
            # reference can still surface real coverage this way.
            if technique_ids:
                behavioral = await find_behavior_rules(session, technique_ids)
                if behavioral:
                    return _build_community_response(
                        cve_id_upper, behavioral, source="community_behavioral",
                    )

        # No community rule (either tier), or forced -> AI generate
        client = LLMClient(get_settings())
        ai_result = await generate_sigma_rule(
            client,
            cve_id=cve_id_upper,
            description=finding_ctx["description"],
            cvss=finding_ctx["cvss"],
            vendor=finding_ctx["vendor"],
            product=finding_ctx["product"],
            version_range=finding_ctx["version_range"],
            cwe_ids=finding_ctx["cwe_ids"],
            attack_techniques=finding_ctx["attack_techniques"],
            kill_chain_phases=finding_ctx["kill_chain_phases"],
        )
        return {
            "cve_id": cve_id_upper,
            "source": "ai_generated",
            "match_confidence": ai_result["confidence"],
            "community_count": 0,
            "primary_rule": {
                "title": f"AI-generated rule for {cve_id_upper}",
                "yaml": ai_result["sigma_yaml"],
                "aql": sigma_yaml_to_aql(ai_result["sigma_yaml"]),
                "source_ref": None,
            },
            "ai_metadata": {
                "confidence": ai_result["confidence"],
                "analyst_notes": ai_result["analyst_notes"],
                "model": ai_result["model"],
            },
        }
