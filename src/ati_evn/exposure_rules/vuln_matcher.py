"""LLM-assisted CVE matching for exposure products.

Flow:
  1. Group exposures by (product, version) tuple (batching — one LLM
     call per unique tuple, not per exposure).
  2. For each unique tuple, query CveProductMap for candidate CVE list.
  3. Send (product, version, candidate_cves) to the LLM.
  4. LLM returns which CVE IDs affect this exact version.
  5. Return {(product, version): [match_dict, ...]}.
"""
from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ati_evn.config import get_settings
from ati_evn.db.models import CveProductMap, Detection, Exposure
from ati_evn.db.session import async_session
from ati_evn.llm.client import LLMClient

logger = logging.getLogger("ati_evn.exposure_rules.vuln")

MATCH_SYSTEM = """You are a CVE-to-version matching expert. Given a
software product, its specific version, and a list of candidate CVEs
that mention this product family, return which CVEs affect this exact
version.

Return JSON ONLY (no markdown fences):
{
  "matches": [
    {
      "cve_id": "CVE-YYYY-NNNNN",
      "confidence": 0.9,
      "reason": "brief technical justification (1 sentence)"
    }
  ]
}

Rules:
1. Only include CVEs whose affected version range covers the given version.
2. Do NOT invent CVE IDs -- use only those in the candidate list.
3. If unsure whether version is affected, include with lower confidence (0.5-0.7).
4. Return empty matches array if none apply. Do not force matches.
5. Confidence 0.9+: version explicitly in affected range.
   Confidence 0.6-0.9: version likely in range (patch-level uncertainty).
   Confidence 0.5-0.6: possibly affected, uncertain.
   Below 0.5: skip (don't include).
"""


async def _load_candidates(session: AsyncSession, product: str, limit: int = 30) -> list[dict]:
    """Return top CVE candidates for a product from cve_product_map,
    with a CVE description snippet from the matching NVD Detection."""
    stmt = (
        select(
            CveProductMap.cve_id, CveProductMap.vendor,
            CveProductMap.product, CveProductMap.version_range,
        )
        .where(CveProductMap.product.ilike(f"%{product}%"))
        .order_by(CveProductMap.cve_id.desc())
        .limit(limit)
    )
    rows = list(await session.execute(stmt))
    candidates = []
    seen_cves: set[str] = set()
    for r in rows:
        cve_id = r.cve_id
        if cve_id in seen_cves:
            continue
        seen_cves.add(cve_id)
        det_row = await session.execute(
            select(Detection.raw_text, Detection.severity).where(
                Detection.ioc_value == cve_id.lower(),
                Detection.source == "nvd",
            ).limit(1)
        )
        det = det_row.first()
        desc = (det[0] or "")[:200] if det else ""
        severity = det[1] if det else None
        candidates.append({
            "cve_id": cve_id,
            "vendor": r.vendor,
            "product": r.product,
            "version_range": r.version_range or "",
            "description": desc,
            "severity": severity.value if severity and hasattr(severity, "value") else None,
        })
    return candidates


async def match_cves_for_product(product: str, version: str) -> tuple[list[dict], list[str]]:
    """Return (matches, errors). Each match dict has cve_id, confidence,
    reason, severity."""
    if not product or not version:
        return [], ["Missing product or version"]

    async with async_session() as session:
        candidates = await _load_candidates(session, product)

    if not candidates:
        return [], []

    settings = get_settings()
    client = LLMClient(settings)

    cand_str = "\n".join(
        f"- {c['cve_id']}: {c['vendor']}/{c['product']} version_range='{c['version_range']}' "
        f"severity={c['severity']} desc={c['description'][:150]}"
        for c in candidates[:25]
    )

    user_prompt = (
        f"Product: {product}\n"
        f"Version: {version}\n\n"
        f"Candidate CVEs (from cve_product_map lookup):\n{cand_str}\n\n"
        f"Which of these CVEs affect this exact version?"
    )

    try:
        raw = await client.chat_json(
            system=MATCH_SYSTEM,
            user=user_prompt,
            max_tokens=2048,
            temperature=0.1,
        )
    except Exception as e:
        logger.exception("LLM vuln match error for %s/%s: %s", product, version, e)
        return [], [f"LLM error: {str(e)[:200]}"]

    if not isinstance(raw, dict):
        return [], ["LLM did not return dict"]

    matches_raw = raw.get("matches") or []
    matches = []
    cand_by_id = {c["cve_id"]: c for c in candidates}
    for m in matches_raw:
        cve_id = (m.get("cve_id") or "").strip().upper()
        if cve_id not in cand_by_id:
            continue  # LLM hallucinated a CVE not in candidates — skip
        confidence = float(m.get("confidence") or 0)
        if confidence < 0.5:
            continue
        matches.append({
            "cve_id": cve_id,
            "confidence": confidence,
            "reason": (m.get("reason") or "")[:300],
            "severity": cand_by_id[cve_id]["severity"],
        })
    return matches, []


async def batch_match_cves(exposures: list[Exposure]) -> dict[tuple[str, str], list[dict]]:
    """Batch by (product, version) tuple — one LLM call per unique tuple."""
    tuples = set()
    for e in exposures:
        if not e.product or not e.version:
            continue
        tuples.add((e.product.lower(), e.version.lower()))

    logger.info(
        "Vuln batch match: %d exposures, %d unique (product,version) tuples",
        len(exposures), len(tuples),
    )

    results: dict[tuple[str, str], list[dict]] = {}
    for product, version in tuples:
        matches, errors = await match_cves_for_product(product, version)
        results[(product, version)] = matches
        if errors:
            logger.warning("Vuln match errors for %s/%s: %s", product, version, errors)
    return results
