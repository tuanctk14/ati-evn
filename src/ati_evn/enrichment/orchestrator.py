"""Enrichment orchestrator.

Public API:
    async def enrich_finding(session, finding, *, smet_mapper=None) -> dict
    def load_smet_lazy(settings) -> AttackBertMapper | None

Wires together the semantic BERT ranker + the CWE→ATT&CK chain backup,
mitigation lookup, kill chain phase lookup. Result is stashed into
Finding.metadata_['attack_context'].
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy import select

from ati_evn.config import get_settings
from ati_evn.db.models import CveCweMap, Detection, Finding
from ati_evn.enrichment.attack_bert import AttackBertMapper, load_mapper_or_none
from ati_evn.enrichment.attack_catalog import (
    get_mitigation_name,
    get_mitigations_for_technique,
    get_tactics_for_technique,
    get_technique_name,
)
from ati_evn.enrichment.cwe_chain import build_chain

logger = logging.getLogger("ati_evn.enrichment.orchestrator")


def load_smet_lazy(settings=None) -> Optional[AttackBertMapper]:
    """Load the ATT&CK-BERT mapper (or MiniLM fallback per settings). Cached.
    Returns None if loading fails; caller falls back to chain-only."""
    settings = settings or get_settings()
    cache_path = Path(settings.smet_embeddings_cache) if hasattr(settings, "smet_embeddings_cache") \
        else Path("./src/ati_evn/data/technique_embeddings.npz")
    model_name = getattr(settings, "attack_bert_model", None) or "basel/ATTACK-BERT"
    device = getattr(settings, "attack_bert_device", None) or "cpu"

    mapper = load_mapper_or_none(model_name, cache_path, device)
    if mapper is None and model_name != "sentence-transformers/all-MiniLM-L6-v2":
        logger.info("Trying fallback model all-MiniLM-L6-v2")
        mapper = load_mapper_or_none(
            "sentence-transformers/all-MiniLM-L6-v2", cache_path, device,
        )
    return mapper


# ══════════════════════════════════════════════════════════════════════════
# Main API
# ══════════════════════════════════════════════════════════════════════════

async def enrich_finding(
    session,
    finding: Finding,
    *,
    smet_mapper: Optional[AttackBertMapper] = None,
) -> dict:
    """Compute attack_context and store in finding.metadata_. Idempotent."""
    if finding.ioc_type == "cve_id":
        ctx = await _enrich_cve(session, finding, smet_mapper)
    elif finding.ioc_type in ("ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"):
        ctx = await _enrich_ioc(session, finding)
    else:
        ctx = {}

    if ctx:
        ctx["enriched_at"] = datetime.now(timezone.utc).isoformat()
        existing = dict(finding.metadata_ or {})
        existing["attack_context"] = ctx
        finding.metadata_ = existing
        await session.flush()

    return ctx


# ══════════════════════════════════════════════════════════════════════════
# CVE branch
# ══════════════════════════════════════════════════════════════════════════

async def _enrich_cve(session, finding, smet_mapper) -> dict:
    cve_id = finding.ioc_value.upper()

    # 1. CWEs from cve_cwe_map (populated by slice 4)
    result = await session.execute(
        select(CveCweMap.cwe_id).where(CveCweMap.cve_id == cve_id)
    )
    cwe_ids = sorted({row[0] for row in result})

    # 2. Description: prefer the NVD-source Detection's raw_text
    result = await session.execute(
        select(Detection.raw_text).where(
            Detection.ioc_value == cve_id.lower(),
            Detection.source == "nvd",
        ).limit(1)
    )
    description = result.scalar_one_or_none() or ""

    # 3. BERT semantic similarity
    smet_predictions = []
    if smet_mapper and description:
        try:
            smet_predictions = await asyncio.to_thread(
                smet_mapper.map, description, top_k=5, min_similarity=0.35,
            )
        except Exception as e:
            logger.warning("BERT map failed for %s: %s", cve_id, e)

    smet_techs = [
        {"id": p.technique_id, "name": p.name,
         "confidence": p.confidence, "source": "smet"}
        for p in smet_predictions
    ]

    # 4. CWE chain (deterministic backup)
    chain = build_chain(cwe_ids)
    chain_techs = []
    for tid in chain.attack_techniques:
        meta = chain.metadata_per_technique.get(tid, {})
        chain_techs.append({
            "id": tid,
            "name": get_technique_name(tid),
            "confidence": round(float(meta.get("confidence") or 0.6), 3),
            "source": "chain",
            "chain_source": meta.get("source"),  # e.g. "top25", "capec_stix"
            "chain_via_cwe": meta.get("cwe"),
            "reason": chain.reason_per_technique.get(tid),
        })

    # 5. Merge — BERT takes precedence on duplicate technique ids
    tech_by_id: dict[str, dict] = {t["id"]: t for t in chain_techs}
    for t in smet_techs:
        tech_by_id[t["id"]] = t
    techniques = list(tech_by_id.values())

    # 6. Mitigations union across all techniques
    mitigation_ids: set[str] = set()
    for t in techniques:
        mitigation_ids.update(get_mitigations_for_technique(t["id"]))
    mitigations = [
        {"id": mid, "name": get_mitigation_name(mid)}
        for mid in sorted(mitigation_ids)
    ]

    # 7. Kill chain phases
    phases: set[str] = set()
    for t in techniques:
        phases.update(get_tactics_for_technique(t["id"]))

    return {
        "techniques": techniques,
        "cwe_ids": cwe_ids,
        "kill_chain_phases": sorted(phases),
        "mitigations": mitigations,
        "smet_used": bool(smet_techs),
        "chain_used": bool(chain_techs),
    }


# ══════════════════════════════════════════════════════════════════════════
# IOC branch (network/malware indicators)
# ══════════════════════════════════════════════════════════════════════════

async def _enrich_ioc(session, finding) -> dict:
    """For IP/domain/URL/hash IOCs, use the source feed's malware family
    tag (if any) as a heuristic hint for kill chain phase and mitigations.

    We don't have a Malware→Technique lookup shipped in this slice (would
    require another data file). Instead we set some sensible defaults per
    IOC type."""
    # Grab metadata from any linked Detection
    result = await session.execute(
        select(Detection.metadata_, Detection.source).where(
            Detection.finding_id == finding.id,
        ).limit(1)
    )
    row = result.first()
    if not row:
        return {}
    meta = row[0] or {}
    source = row[1] or ""

    malware = (
        meta.get("malware_printable") or meta.get("malware") or
        meta.get("signature") or meta.get("threat")
    )

    # Rough per-ioc-type defaults — a hint, not a claim
    ioc_defaults: dict[str, tuple[list[str], list[str]]] = {
        # (technique_ids, kill_chain_phases)
        "ipv4":   (["T1071"], ["command-and-control"]),
        "ipv6":   (["T1071"], ["command-and-control"]),
        "domain": (["T1071", "T1071.001"], ["command-and-control"]),
        "url":    (["T1189", "T1204"], ["initial-access", "execution"]),
        "md5":    (["T1204.002"], ["execution"]),
        "sha1":   (["T1204.002"], ["execution"]),
        "sha256": (["T1204.002"], ["execution"]),
    }
    tech_ids, phases = ioc_defaults.get(finding.ioc_type, ([], []))
    if not tech_ids:
        return {}

    techniques = [
        {"id": tid, "name": get_technique_name(tid), "confidence": 0.5,
         "source": "ioc-heuristic"}
        for tid in tech_ids
    ]
    mitigation_ids: set[str] = set()
    for tid in tech_ids:
        mitigation_ids.update(get_mitigations_for_technique(tid))
    mitigations = [
        {"id": mid, "name": get_mitigation_name(mid)}
        for mid in sorted(mitigation_ids)
    ]

    ctx = {
        "techniques": techniques,
        "cwe_ids": [],
        "kill_chain_phases": phases,
        "mitigations": mitigations,
        "smet_used": False,
        "chain_used": False,
        "ioc_heuristic_used": True,
    }
    if malware:
        ctx["malware_family_hint"] = malware
    if source:
        ctx["feed_source"] = source
    return ctx
