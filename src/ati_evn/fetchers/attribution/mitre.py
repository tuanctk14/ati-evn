"""MITRE ATT&CK Enterprise technique lookup.

Uses the pre-trimmed dataset shipped in ati_evn/data/mitre_attack_enterprise.json
(sourced from the official STIX bundle at github.com/mitre/cti, reduced to only
the fields this module needs — 697 techniques, ~884KB, keyed by technique ID).

Public API:
    get_technique(technique_id) -> dict | None
    format_technique(technique_id) -> str   (human-readable for Telegram)
    search_by_keyword(term) -> list[dict]   (case-insensitive over name+description)

Parent fallback: `T1059.001` will fall back to `T1059` if the sub-technique
isn't present. `T1190` is used as the final default so any downstream
component that needs *some* technique always gets one.
"""
from __future__ import annotations

import functools
import json
import logging
from importlib import resources
from typing import Optional

logger = logging.getLogger("ati_evn.attribution.mitre")


@functools.lru_cache(maxsize=1)
def _load_db() -> dict[str, dict]:
    """Load & cache the MITRE dataset. Called once per process."""
    try:
        data_pkg = resources.files("ati_evn.data")
        with data_pkg.joinpath("mitre_attack_enterprise.json").open(
            "r", encoding="utf-8"
        ) as f:
            bundle = json.load(f)
        techniques = bundle.get("techniques") or {}
        logger.info("MITRE ATT&CK loaded: %d techniques", len(techniques))
        return techniques
    except Exception as e:
        logger.error("Failed to load MITRE dataset: %s", e)
        return {}


def get_technique(technique_id: str) -> Optional[dict]:
    """Return the technique dict, or the parent's dict for a sub-technique fallback.

    Sub-technique fallback: `T1059.001` → try direct → fall back to `T1059`.
    Returns None if neither the sub-technique nor its parent is known.
    """
    if not technique_id:
        return None
    tid = technique_id.upper().strip()
    db = _load_db()

    if tid in db:
        return db[tid]

    if "." in tid:
        parent = tid.split(".", 1)[0]
        if parent in db:
            hit = dict(db[parent])
            hit["_fallback"] = f"showing parent {parent}"
            return hit

    return None


def get_technique_or_default(technique_id: str, default_id: str = "T1190") -> dict:
    """Same as get_technique but always returns a technique — falls back to
    `T1190` (Exploit Public-Facing Application) if the requested ID isn't
    found. Useful when a caller needs to guarantee some ATT&CK context.
    """
    hit = get_technique(technique_id)
    if hit:
        return hit
    fallback = _load_db().get(default_id) or {}
    return {**fallback, "_fallback": f"unknown {technique_id}, defaulted to {default_id}"}


def format_technique(technique_id: str) -> str:
    """Human-readable multiline summary — suitable for Telegram messages."""
    hit = get_technique(technique_id)
    if not hit:
        return f"MITRE {technique_id}: (không tìm thấy)"

    fallback_note = f"  [{hit['_fallback']}]" if hit.get("_fallback") else ""
    return (
        f"MITRE {technique_id}{fallback_note}\n"
        f"  Name:       {hit.get('name', '?')}\n"
        f"  Tactic:     {hit.get('tactic', '?')} ({hit.get('tactic_id', '?')})\n"
        f"  Description: {(hit.get('description') or '').strip()[:400]}\n"
        f"  Detection:  {(hit.get('detection') or 'no guidance').strip()[:300]}\n"
        f"  Mitigation: {(hit.get('mitigation') or 'no guidance').strip()[:300]}\n"
        f"  Platforms:  {', '.join(hit.get('platforms') or []) or '?'}"
    )


def search_by_keyword(term: str, limit: int = 10) -> list[dict]:
    """Case-insensitive search over technique name + description. Returns list
    of {id, name, tactic, tactic_id} for the top `limit` matches. Cheap enough
    for on-demand analyst chat queries — no index needed at 697 rows.
    """
    if not term or len(term) < 2:
        return []
    needle = term.lower()
    hits: list[tuple[int, str, dict]] = []
    for tid, t in _load_db().items():
        name = (t.get("name") or "").lower()
        desc = (t.get("description") or "").lower()
        score = 0
        if needle in name:
            score += 10
        if needle in desc:
            score += 1
        if score:
            hits.append((score, tid, t))

    hits.sort(key=lambda x: (-x[0], x[1]))
    out = []
    for _, tid, t in hits[:limit]:
        out.append({
            "id": tid,
            "name": t.get("name"),
            "tactic": t.get("tactic"),
            "tactic_id": t.get("tactic_id"),
        })
    return out
