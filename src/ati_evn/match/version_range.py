"""CVE version_range membership check.

cve_product_map.version_range stores NVD-derived ranges like:
    ">= 4.5.0, < 4.5.7"     (bounded)
    "<= 3.2.1"              (upper only)
    ">= 2.0"                (lower only)
    "= 1.4.3"               (single fixed version)
    None / ""               (unknown — NVD gave no version constraint)

We reuse `packaging.specifiers.SpecifierSet`, which is PEP 440 and expects
operators glued to the version with no space (">=4.5.0" not ">= 4.5.0") and
"==" instead of "=". We normalize before handing off.

Confidence policy (documented here since callers need to build
ProbableExposure vs. Finding decisions from `reason`):
- Both version and range present and range is satisfiable  -> confirmed match
- version missing                                          -> 'no_version'  (0.5)
- range missing                                            -> 'no_range'    (0.6)
- either fails to parse (garbage/pre-release suffixes NVD sometimes emits,
  e.g. "1.2.3-rc.4-patch5")                                -> 'unparseable' (0.4)
Callers (strategies.py) own the actual confidence values; this module only
returns the reason string.
"""
from __future__ import annotations

import logging

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

logger = logging.getLogger("ati_evn.match.version_range")


def _normalize_range(range_str: str) -> str:
    """Turn an NVD-style range string into a PEP 440 SpecifierSet string."""
    parts = [p.strip() for p in range_str.split(",") if p.strip()]
    normalized = []
    for part in parts:
        if part.startswith("==") or part.startswith(">=") or part.startswith("<=") \
                or part.startswith("!="):
            op, rest = part[:2], part[2:]
        elif part.startswith(">") or part.startswith("<"):
            op, rest = part[:1], part[1:]
        elif part.startswith("="):
            op, rest = "==", part[1:]
        else:
            # No recognizable operator — assume exact match.
            op, rest = "==", part
        normalized.append(f"{op}{rest.strip()}")
    return ",".join(normalized)


def version_in_range(version_str: str | None, range_str: str | None) -> tuple[bool, str]:
    """Return (in_range, reason).

    reason in {'match_exact', 'match_range', 'no_range', 'no_version',
               'out_of_range', 'unparseable'}.
    """
    if not version_str:
        return False, "no_version"

    if not range_str or not range_str.strip():
        return True, "no_range"

    try:
        version = Version(version_str.strip())
    except InvalidVersion:
        return False, "unparseable"

    normalized_range = _normalize_range(range_str)

    try:
        specifier_set = SpecifierSet(normalized_range)
    except InvalidSpecifier:
        logger.warning("Unparseable version_range %r (normalized=%r)", range_str, normalized_range)
        return False, "unparseable"

    if version not in specifier_set:
        return False, "out_of_range"

    # A single "==x.y.z" specifier is a fixed-version match; anything with
    # a comparison operator (>=, <, etc.) is a bounded range match.
    if all(s.operator == "==" for s in specifier_set):
        return True, "match_exact"
    return True, "match_range"
