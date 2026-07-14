"""CWE → ATT&CK chain (deterministic backup).

When BERT semantic similarity fails or isn't wanted, the CWE list acts as
the backup path to ATT&CK techniques via a merged mapping that combines:
  - MITRE CAPEC STIX chain (CWE → CAPEC → ATT&CK, 149 CWE)
  - CWE Top 25 (2023) curated ground truth (25 CWE)
  - Common implementation weakness curation (~25 CWE)
  - Legacy ati_src curated (9 CWE unique)

Total ~185 CWE entries with confidence scoring (0.7-0.95).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ati_evn.enrichment.attack_catalog import get_cwe_entry


@dataclass
class ChainResult:
    attack_techniques: list[str] = field(default_factory=list)
    reason_per_technique: dict[str, str] = field(default_factory=dict)
    # Per-technique metadata: {tid: {cwe, confidence, source}}
    metadata_per_technique: dict[str, dict] = field(default_factory=dict)


def build_chain(cwe_ids: list[str]) -> ChainResult:
    """Given a list of CWE IDs, return the union of ATT&CK techniques mapped
    to any of them via the curated map. When multiple CWEs point to the same
    technique, keep the highest-confidence attribution."""
    tech_meta: dict[str, dict] = {}  # tid → {cwe, confidence, source, reasoning}

    for cwe in cwe_ids or []:
        entry = get_cwe_entry(cwe)
        if not entry:
            continue
        techs = entry.get("techniques") or []
        conf = float(entry.get("confidence") or 0.5)
        source = entry.get("source") or "unknown"
        reasoning = entry.get("reasoning") or ""

        for tid in techs:
            if tid not in tech_meta or tech_meta[tid]["confidence"] < conf:
                tech_meta[tid] = {
                    "cwe": cwe, "confidence": conf,
                    "source": source, "reasoning": reasoning,
                }

    reasons = {
        tid: f"via {m['cwe']} ({m['source']}, conf {m['confidence']:.2f})"
        for tid, m in tech_meta.items()
    }
    return ChainResult(
        attack_techniques=sorted(tech_meta.keys()),
        reason_per_technique=reasons,
        metadata_per_technique=tech_meta,
    )
