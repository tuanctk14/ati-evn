"""Match a normalized file dict against loaded document leak rules.

Matching happens before insert, so `doc` here is a plain dict (from
grayhat_client._normalize_file), not an ORM object.
"""
from __future__ import annotations

import re

from ati_evn.document_rules.loader import load_rules

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _condition_matches(condition: dict, doc: dict) -> bool:
    if "filename_pattern" in condition:
        pat = re.compile(condition["filename_pattern"], re.IGNORECASE)
        filename = doc.get("filename") or ""
        file_path = doc.get("file_path") or ""
        if not (pat.search(filename) or pat.search(file_path)):
            return False
    if "extension_in" in condition:
        allowed = [e.lower() for e in condition["extension_in"]]
        ext = (doc.get("file_extension") or "").lower()
        if ext not in allowed:
            return False
    return True


def match_document_rule(doc: dict) -> dict | None:
    """Return the first matching rule (highest severity first) or None."""
    rules = load_rules()
    sorted_rules = sorted(rules, key=lambda r: _SEVERITY_ORDER.get(r["severity"], 9))
    for rule in sorted_rules:
        try:
            if _condition_matches(rule["condition"], doc):
                return rule
        except re.error:
            continue
    return None
