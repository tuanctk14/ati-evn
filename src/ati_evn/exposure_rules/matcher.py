"""Match one Exposure against loaded rules. Return list of matched rules."""
from __future__ import annotations

import logging

from ati_evn.db.models import Exposure
from ati_evn.exposure_rules.loader import load_rules

logger = logging.getLogger("ati_evn.exposure_rules.matcher")


def _condition_matches(condition: dict, exposure: Exposure) -> bool:
    """Evaluate one condition dict against an Exposure ORM object."""
    if "service" in condition:
        svc = (exposure.service_name or "").lower()
        expected = str(condition["service"]).lower()
        if svc != expected:
            return False
    if "auth_required" in condition:
        if exposure.auth_required != condition["auth_required"]:
            return False
    if "tls_version_in" in condition:
        versions = condition["tls_version_in"]
        if exposure.tls_version not in versions:
            return False
    if "capability" in condition:
        cap = condition["capability"]
        caps = exposure.capabilities or {}
        if not caps.get(cap):
            return False
    return True


def match_rules(exposure: Exposure) -> list[dict]:
    """Return list of matched rule dicts for this exposure."""
    rules = load_rules()
    matched = []
    for rule in rules:
        try:
            if _condition_matches(rule["condition"], exposure):
                matched.append(rule)
        except Exception as e:
            logger.warning("Rule %s evaluation failed: %s", rule["id"], e)
    return matched
