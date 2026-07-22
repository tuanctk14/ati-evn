"""YAML rule loader for document leaks."""
from __future__ import annotations

import functools
import logging
from importlib import resources

import yaml

logger = logging.getLogger("ati_evn.document_rules.loader")

VALID_SEVERITIES = {"critical", "high", "medium", "low"}


@functools.lru_cache(maxsize=1)
def load_rules() -> list[dict]:
    data_pkg = resources.files("ati_evn.data")
    with data_pkg.joinpath("document_leak_rules.yaml").open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    raw = data.get("rules") or []
    validated: list[dict] = []
    for r in raw:
        if not r.get("id") or not r.get("condition"):
            continue
        if (r.get("severity") or "").lower() not in VALID_SEVERITIES:
            continue
        if not r.get("enabled", True):
            continue
        validated.append({
            "id": r["id"],
            "condition": r["condition"],
            "severity": r["severity"].lower(),
            "title": r.get("title") or r["id"],
            "description": (r.get("description") or "").strip(),
        })
    logger.info("Loaded %d document leak rules", len(validated))
    return validated
