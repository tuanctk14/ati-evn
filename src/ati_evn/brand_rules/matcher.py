"""Match a normalized urlscan sighting dict against loaded brand abuse rules.

Matching happens before insert, so `sighting` here is a plain dict (from
urlscan_client._normalize_search_row + _normalize_verdicts), not an ORM
object.
"""
from __future__ import annotations

from ati_evn.brand_rules.loader import load_rules

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _title_matches_brand(sighting: dict) -> bool:
    title = (sighting.get("page_title") or "").lower()
    keyword = (sighting.get("keyword_matched") or "").lower()
    return bool(keyword) and keyword in title


def _domain_not_evn(sighting: dict, evn_domains: list[str]) -> bool:
    domain = (sighting.get("domain") or "").lower()
    return bool(domain) and domain not in {d.lower() for d in evn_domains}


def _condition_matches(condition: dict, sighting: dict, evn_domains: list[str]) -> bool:
    if "verdict_malicious" in condition:
        if bool(sighting.get("verdict_malicious")) != condition["verdict_malicious"]:
            return False
    if "engines_malicious_total_gte" in condition:
        total = sighting.get("engines_malicious_total") or 0
        if total < condition["engines_malicious_total_gte"]:
            return False
    if "title_matches_brand" in condition:
        if _title_matches_brand(sighting) != condition["title_matches_brand"]:
            return False
    if "domain_not_evn" in condition:
        if _domain_not_evn(sighting, evn_domains) != condition["domain_not_evn"]:
            return False
    return True


def match_brand_rule(sighting: dict, evn_domains: list[str]) -> dict | None:
    """Return the first matching rule (highest severity first) or None."""
    rules = load_rules()
    sorted_rules = sorted(rules, key=lambda r: _SEVERITY_ORDER.get(r["severity"], 9))
    for rule in sorted_rules:
        if _condition_matches(rule["condition"], sighting, evn_domains):
            return rule
    return None
