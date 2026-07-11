"""The 5 match strategies. Each is a pure function: (Detection, AssetIndex) ->
list[MatchResult]. No DB access here — customer_router.py owns persistence.
"""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass

from ati_evn.db.models import CustomerAsset, Detection
from ati_evn.match.asset_index import AssetIndex
from ati_evn.match.domain_utils import domain_matches, extract_host_from_url
from ati_evn.match.version_range import version_in_range

logger = logging.getLogger("ati_evn.match.strategies")


@dataclass
class MatchResult:
    customer_id: int
    asset: CustomerAsset
    correlation_type: str
    confidence: float
    reason: str
    is_probable: bool = False
    cve_context: dict | None = None


# ── Strategy 1: exact IP ──────────────────────────────────────────────────────

def match_exact_ip(det: Detection, idx: AssetIndex) -> list[MatchResult]:
    if det.ioc_type not in ("ipv4", "ipv6"):
        return []

    candidates = idx.ip_lookup.get(det.ioc_value.strip().lower(), [])
    return [
        MatchResult(
            customer_id=customer_id,
            asset=asset,
            correlation_type="exact_ip",
            confidence=0.95,
            reason=f"IOC IP {det.ioc_value} exactly matches customer asset {asset.asset_value}",
        )
        for customer_id, asset in candidates
    ]


# ── Strategy 2: CIDR ──────────────────────────────────────────────────────────

def match_cidr(det: Detection, idx: AssetIndex) -> list[MatchResult]:
    if det.ioc_type not in ("ipv4", "ipv6"):
        return []

    try:
        ip_obj = ipaddress.ip_address(det.ioc_value.strip())
    except ValueError:
        return []

    results: list[MatchResult] = []
    for network, customer_id, asset in idx.cidr_networks:
        try:
            if ip_obj in network:
                results.append(MatchResult(
                    customer_id=customer_id,
                    asset=asset,
                    correlation_type="cidr",
                    confidence=0.85,
                    reason=f"IOC IP {det.ioc_value} falls inside customer CIDR {asset.asset_value}",
                ))
        except TypeError:
            # IPv4 address vs IPv6 network (or vice versa) — not a match.
            continue
    return results


# ── Strategy 3: domain boundary ───────────────────────────────────────────────

def match_domain(det: Detection, idx: AssetIndex) -> list[MatchResult]:
    if det.ioc_type not in ("domain", "url", "subdomain"):
        return []

    if det.ioc_type == "url":
        host = (det.metadata_ or {}).get("host") or extract_host_from_url(det.ioc_value)
    else:
        host = det.ioc_value

    if not host:
        return []

    results: list[MatchResult] = []
    for customer_domain, customer_id, asset in idx.domain_records:
        matched, correlation_type = domain_matches(host, customer_domain)
        if not matched:
            continue
        confidence = 0.95 if correlation_type == "exact_domain" else 0.90
        results.append(MatchResult(
            customer_id=customer_id,
            asset=asset,
            correlation_type=correlation_type,
            confidence=confidence,
            reason=f"IOC host {host} is {correlation_type} of customer asset {asset.asset_value}",
        ))
    return results


# ── Strategy 4: CVE → product ─────────────────────────────────────────────────

def _candidate_devices(idx: AssetIndex, vendor: str, product: str) -> list[tuple[int, CustomerAsset]]:
    seen_ids: set[int] = set()
    candidates: list[tuple[int, CustomerAsset]] = []

    for customer_id, asset in idx.devices_by_vendor.get(vendor.lower(), []):
        if asset.id in seen_ids:
            continue
        asset_product = (asset.product or "").lower()
        product_lower = product.lower()
        if product_lower in asset_product or asset_product in product_lower:
            candidates.append((customer_id, asset))
            seen_ids.add(asset.id)

    return candidates


_PROBABLE_CONFIDENCE = {
    "no_range": 0.6,
    "no_version": 0.5,
    "unparseable": 0.4,
}


def match_cve_product(det: Detection, idx: AssetIndex) -> list[MatchResult]:
    if det.ioc_type != "cve_id":
        return []

    cpm_rows = idx.cve_product_map.get(det.ioc_value.strip().upper(), [])
    if not cpm_rows:
        return []

    metadata = det.metadata_ or {}
    cvss_score = metadata.get("cvss_score")

    results: list[MatchResult] = []
    for cpm in cpm_rows:
        if not cpm.vendor or not cpm.product:
            continue

        for customer_id, asset in _candidate_devices(idx, cpm.vendor, cpm.product):
            in_range, reason = version_in_range(asset.version, cpm.version_range)

            cve_context = {
                "cve_id": det.ioc_value,
                "cvss_score": cpm.cvss_score if cpm.cvss_score is not None else cvss_score,
                "actively_exploited": bool(cpm.actively_exploited),
                "vendor": cpm.vendor,
                "product": cpm.product,
            }

            if in_range and reason in ("match_exact", "match_range"):
                results.append(MatchResult(
                    customer_id=customer_id,
                    asset=asset,
                    correlation_type="cve_product",
                    confidence=0.9,
                    reason=(f"{det.ioc_value} affects {cpm.vendor}/{cpm.product} "
                            f"({reason}) on asset {asset.asset_value} v{asset.version}"),
                    is_probable=False,
                    cve_context=cve_context,
                ))
            elif reason in ("no_range", "no_version", "unparseable"):
                results.append(MatchResult(
                    customer_id=customer_id,
                    asset=asset,
                    correlation_type="cve_probable",
                    confidence=_PROBABLE_CONFIDENCE[reason],
                    reason=(f"{det.ioc_value} probably affects {cpm.vendor}/{cpm.product} "
                            f"on asset {asset.asset_value} ({reason})"),
                    is_probable=True,
                    cve_context=cve_context,
                ))
            # reason == 'out_of_range' -> confirmed NOT affected, no result.

    return results


# ── Strategy 5: keyword / brand ───────────────────────────────────────────────

def match_keyword(det: Detection, idx: AssetIndex) -> list[MatchResult]:
    if not idx.keyword_patterns:
        return []

    haystacks = [det.raw_text or ""]
    if det.metadata_:
        haystacks.append(str(det.metadata_))
    text = " ".join(haystacks)
    if not text.strip():
        return []

    results: list[MatchResult] = []
    for pattern, customer_id, asset, kind in idx.keyword_patterns:
        if pattern.search(text):
            results.append(MatchResult(
                customer_id=customer_id,
                asset=asset,
                correlation_type=kind,
                confidence=0.6,
                reason=f"{kind.capitalize()} '{asset.asset_value}' found in detection text/metadata",
            ))
    return results


ALL_STRATEGIES = [
    match_exact_ip,
    match_cidr,
    match_domain,
    match_cve_product,
    match_keyword,
]
