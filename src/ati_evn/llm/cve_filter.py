"""Decide whether a CVE should trigger LLM CPE/CWE inference.

Rule: LLM is called only when a CVE has structured data gaps AND the
CVE's textual context suggests it's relevant to at least one EVN vendor.

Trigger: (missing CPE OR missing CWE) AND (description mentions any EVN
vendor OR any reference URL is hosted at any EVN vendor's domain).

This keeps LLM spend proportional to what could plausibly match an EVN
asset, instead of running on every CVE NVD hasn't fully annotated yet
(the vast majority of which — an npm package, a WordPress plugin — could
never match our inventory).
"""
from __future__ import annotations

import re
from urllib.parse import urlparse


def _vendor_word_pattern(vendor: str) -> re.Pattern:
    return re.compile(rf"\b{re.escape(vendor.lower())}\b", re.IGNORECASE)


def cve_description_mentions_vendor(description: str, evn_vendors: set[str]) -> str | None:
    """Return the matched vendor name, or None."""
    if not description:
        return None
    desc = description.lower()
    for v in evn_vendors:
        if _vendor_word_pattern(v).search(desc):
            return v
    return None


def cve_reference_url_mentions_vendor(
    references: list[dict], evn_vendors: set[str],
) -> tuple[str, str] | None:
    """Check each reference URL. Return (vendor, url) or None.

    A URL matches vendor V if V appears as a whole hostname label (split by
    dot) — not a substring. This excludes both accidental substring matches
    ("securitysiemens.tk") and marketing/blog subdomains that merely mention
    a vendor in the path rather than being hosted by them.
    """
    for ref in references or []:
        url = (ref.get("url") or "").strip()
        if not url:
            continue
        host = urlparse(url).hostname or ""
        parts = host.lower().split(".")
        for v in evn_vendors:
            if v.lower() in parts:
                return (v, url)
    return None


def should_run_llm(
    *, has_cpe: bool, has_cwe: bool,
    description: str, references: list[dict],
    evn_vendors: set[str],
) -> tuple[bool, str]:
    """Return (should_call, reason)."""
    if has_cpe and has_cwe:
        return False, "cpe+cwe already present"
    if not evn_vendors:
        return False, "no evn vendors configured"

    desc_hit = cve_description_mentions_vendor(description, evn_vendors)
    if desc_hit:
        gap = "cpe" if not has_cpe else "cwe" if not has_cwe else "both"
        return True, f"description mentions '{desc_hit}' (missing {gap})"

    url_hit = cve_reference_url_mentions_vendor(references, evn_vendors)
    if url_hit:
        v, u = url_hit
        gap = "cpe" if not has_cpe else "cwe" if not has_cwe else "both"
        return True, f"reference URL hosts '{v}' at {u} (missing {gap})"

    return False, "no evn vendor in description or references"
