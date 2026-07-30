"""Domain boundary matching.

A prior system (arguswatch) matched customer domains with naive
`ILIKE %customer%`, which matched "chat.com" inside "arguswatch.com" and
"evncrooks.com" against customer "evn.com" — pure substring matches with no
notion of a domain boundary. This module fixes that: matching is always
label-boundary aware (a subdomain must be separated by a literal ".").

Direction matters too: the customer's registered asset is the "smaller"
(more specific or equal) domain, and the IOC is the "bigger" (potentially
more specific) domain being checked against it. We only match when the IOC
domain IS the customer domain, or is a strict subdomain of it — never the
reverse. Otherwise a broad IOC like "evn.com" would incorrectly match a
customer asset "npc.evn.com" even though EVN doesn't control the whole
"evn.com" apex the same way (and more importantly, the IOC is broader than
what the customer told us they own).
"""
from __future__ import annotations

from urllib.parse import urlparse


def _normalize(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def domain_matches(ioc_domain: str, customer_domain: str) -> tuple[bool, str]:
    """Return (matches, correlation_type).

    correlation_type in {'exact_domain', 'subdomain', 'no_match'}.
    """
    ioc = _normalize(ioc_domain)
    customer = _normalize(customer_domain)

    if not ioc or not customer:
        return False, "no_match"

    if ioc == customer:
        return True, "exact_domain"

    if ioc.endswith("." + customer) and len(ioc) > len(customer):
        return True, "subdomain"

    return False, "no_match"


def extract_host_from_url(url: str) -> str | None:
    """urlparse-based host extraction, lowercased, port stripped."""
    try:
        parsed = urlparse(url.strip())
        host = parsed.hostname
        return host.lower() if host else None
    except Exception:
        return None  # malformed URL is an expected input case, not a bug -- caller treats None as "no host"
