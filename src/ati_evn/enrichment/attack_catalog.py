"""Static ATT&CK catalog loader.

Wraps the 4 JSON files shipped in ati_evn/data/:
  - mitre_attack_enterprise.json  — 846 techniques (name, description, tactic, ...)
  - attack_mitigations.json       — 44 M-mitigations + Technique→Mitigations map
  - cwe_to_attack.json            — curated CWE→Technique fallback
  - attack_software.json          — 821 S-series software (malware/tools) +
                                     name index for Malware family lookups

Loaded once per process (module-level, lazy). All lookups are O(1) dict access
after load.
"""
from __future__ import annotations

import functools
import json
import logging
from importlib import resources

logger = logging.getLogger("ati_evn.enrichment.catalog")


@functools.lru_cache(maxsize=1)
def _load_techniques() -> dict[str, dict]:
    """Return {technique_id: {name, tactic, description, ...}}."""
    data_pkg = resources.files("ati_evn.data")
    with data_pkg.joinpath("mitre_attack_enterprise.json").open("r", encoding="utf-8") as f:
        bundle = json.load(f)
    techs = bundle.get("techniques") or {}
    logger.info("ATT&CK techniques loaded: %d", len(techs))
    return techs


@functools.lru_cache(maxsize=1)
def _load_mitigations() -> dict:
    data_pkg = resources.files("ati_evn.data")
    with data_pkg.joinpath("attack_mitigations.json").open("r", encoding="utf-8") as f:
        d = json.load(f)
    logger.info(
        "ATT&CK mitigations loaded: %d mitigations, %d techniques with mitigations",
        len(d.get("mitigations") or {}),
        len(d.get("technique_to_mitigations") or {}),
    )
    return d


@functools.lru_cache(maxsize=1)
def _load_cwe_map() -> dict[str, dict]:
    """Load CWE→ATT&CK map. Handles both v1 (flat lists) and v2 (rich entries).

    v2 schema per CWE:
        {"techniques": [...], "source": "top25|capec_stix|curated|ati_src_curated",
         "confidence": 0.0-1.0, "reasoning": "...", "parent_used": null | "CWE-X"}
    v1 schema per CWE:
        [<technique_id>, ...]      (flat list)

    Returns normalized to v2 shape regardless of source file schema.
    """
    data_pkg = resources.files("ati_evn.data")
    with data_pkg.joinpath("cwe_to_attack.json").open("r", encoding="utf-8") as f:
        d = json.load(f)
    m = d.get("cwe_to_attack") or {}
    schema_version = (d.get("_meta") or {}).get("schema_version", 1)

    normalized: dict[str, dict] = {}
    if schema_version >= 2:
        normalized = m
    else:
        # migrate v1 flat lists → v2 rich entries with default confidence
        for cwe, techs in m.items():
            normalized[cwe] = {
                "techniques": list(techs),
                "source": "ati_src_curated",
                "confidence": 0.75,
                "reasoning": "Curated fallback (schema v1)",
                "parent_used": None,
            }
    logger.info("CWE→ATT&CK map: %d entries (schema v%d)", len(normalized), schema_version)
    return normalized


@functools.lru_cache(maxsize=1)
def _load_software() -> dict:
    data_pkg = resources.files("ati_evn.data")
    with data_pkg.joinpath("attack_software.json").open("r", encoding="utf-8") as f:
        d = json.load(f)
    logger.info(
        "ATT&CK software loaded: %d software, %d techniques mapped, "
        "%d name index",
        len(d.get("software") or {}),
        len(d.get("software_to_techniques") or {}),
        len(d.get("name_to_software") or {}),
    )
    return d


# ── Public lookups ─────────────────────────────────────────────────────────

def get_technique_name(technique_id: str) -> str:
    """Return technique name, or the id itself if unknown."""
    t = _load_techniques().get(technique_id.upper())
    if t:
        return t.get("name") or technique_id
    # Sub-technique fallback: T1059.001 → T1059
    if "." in technique_id:
        parent = technique_id.split(".", 1)[0]
        t = _load_techniques().get(parent)
        if t:
            return t.get("name") or technique_id
    return technique_id


def get_technique_description(technique_id: str) -> str:
    t = _load_techniques().get(technique_id.upper())
    return (t.get("description") if t else "") or ""


def get_all_techniques() -> dict[str, dict]:
    """Return all technique dicts. Used for pre-computing embeddings."""
    return _load_techniques()


def get_mitigations_for_technique(technique_id: str) -> list[str]:
    """Return list of Mitigation IDs (M-series) applicable to this technique.
    Falls back to parent technique for sub-techniques."""
    m = _load_mitigations()
    t2m = m.get("technique_to_mitigations") or {}
    tid = technique_id.upper()
    result = t2m.get(tid) or []
    if not result and "." in tid:
        result = t2m.get(tid.split(".", 1)[0]) or []
    return list(result)


def get_mitigation_name(mitigation_id: str) -> str:
    m = _load_mitigations().get("mitigations", {}).get(mitigation_id.upper())
    return (m.get("name") if m else mitigation_id) or mitigation_id


def get_mitigation_description(mitigation_id: str) -> str:
    m = _load_mitigations().get("mitigations", {}).get(mitigation_id.upper())
    return (m.get("description") if m else "") or ""


def get_tactics_for_technique(technique_id: str) -> list[str]:
    """Return kill chain phases (tactics) for a technique. E.g.
    'initial-access', 'execution'."""
    d = _load_mitigations()
    t2t = d.get("technique_to_tactics") or {}
    tid = technique_id.upper()
    result = t2t.get(tid) or []
    if not result and "." in tid:
        result = t2t.get(tid.split(".", 1)[0]) or []
    return list(result)


def get_techniques_for_cwe(cwe_id: str) -> list[str]:
    """Return list of Technique IDs from the curated CWE fallback map.
    cwe_id format: 'CWE-79' or '79'."""
    entry = get_cwe_entry(cwe_id)
    return list(entry.get("techniques") or []) if entry else []


def get_cwe_entry(cwe_id: str) -> dict | None:
    """Return full entry for a CWE (v2 schema): techniques + source + confidence
    + reasoning + parent_used. Returns None if unknown."""
    if not cwe_id:
        return None
    key = cwe_id if cwe_id.upper().startswith("CWE-") else f"CWE-{cwe_id}"
    return _load_cwe_map().get(key.upper())


def is_technique_revoked(technique_id: str) -> bool:
    """Check if a technique is marked revoked in the catalog (still has a
    name for display — MITRE keeps revoked entries around after
    reorganizing the taxonomy, e.g. splitting one technique into several
    sub-techniques)."""
    t = _load_techniques().get(technique_id.upper())
    return bool(t and t.get("revoked"))


def lookup_software_by_name(malware_name: str) -> str | None:
    """Given a malware/tool name (case-insensitive, tolerates space
    and hyphen variations), return S-series ID or None.

    Uses aggressive normalization to match feed-provided names against
    MITRE's canonical names + aliases.
    """
    if not malware_name:
        return None
    d = _load_software()
    idx = d.get("name_to_software") or {}
    # Try exact + case-insensitive
    key = malware_name.lower().strip()
    if key in idx:
        return idx[key]
    # Try normalized (strip whitespace, hyphens, underscores)
    norm = key.replace(" ", "").replace("-", "").replace("_", "").replace(".", "")
    return idx.get(norm)


def get_techniques_for_software(software_id: str) -> list[str]:
    """Return list of ATT&CK technique IDs that this software uses."""
    d = _load_software()
    return list((d.get("software_to_techniques") or {}).get(software_id) or [])


def get_software_name(software_id: str) -> str:
    d = _load_software()
    s = (d.get("software") or {}).get(software_id) or {}
    return s.get("name") or software_id


# ── Counts (for smoke-test scripts) ────────────────────────────────────────

TECHNIQUE_COUNT = len(_load_techniques())
MITIGATION_COUNT = len(_load_mitigations().get("mitigations") or {})
CWE_MAP_SIZE = len(_load_cwe_map())
SOFTWARE_COUNT = len(_load_software().get("software") or {})
