"""YAML rule loader with validation + caching."""
from __future__ import annotations

import functools
import logging
from importlib import resources

import yaml

logger = logging.getLogger("ati_evn.exposure_rules.loader")

VALID_TYPES = {"service", "configuration"}
VALID_SEVERITIES = {"critical", "high", "medium", "low"}


@functools.lru_cache(maxsize=1)
def load_rules() -> list[dict]:
    """Load and validate exposure_rules.yaml."""
    data_pkg = resources.files("ati_evn.data")
    with data_pkg.joinpath("exposure_rules.yaml").open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    raw_rules = data.get("rules") or []
    validated: list[dict] = []

    for r in raw_rules:
        if not r.get("id") or not r.get("type") or not r.get("condition"):
            logger.warning("Skipping rule missing required fields: %r", r)
            continue
        if r["type"] not in VALID_TYPES:
            logger.warning("Rule %s has invalid type: %s", r["id"], r["type"])
            continue
        if (r.get("severity") or "").lower() not in VALID_SEVERITIES:
            logger.warning("Rule %s has invalid severity", r["id"])
            continue
        if not r.get("enabled", True):
            continue
        validated.append({
            "id": r["id"],
            "type": r["type"],
            "condition": r["condition"],
            "severity": r["severity"].lower(),
            "title": r.get("title") or r["id"],
            "description": (r.get("description") or "").strip(),
        })

    logger.info("Loaded %d exposure rules", len(validated))
    return validated
