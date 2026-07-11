"""In-memory lookup structures for the matcher, built once per run.

With ~2000 Detections × 5 strategies, doing a SQL query per (detection,
strategy) pair would mean tens of thousands of round trips. The full
CustomerAsset + CveProductMap tables are tiny (well under 10MB even at
10x our current seed size), so we load everything into memory once and
do all comparisons in Python.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ati_evn.db.models import AssetType, CustomerAsset, CveProductMap

logger = logging.getLogger("ati_evn.match.asset_index")

_DOMAIN_ASSET_TYPES = {AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.EMAIL_DOMAIN}
_KEYWORD_ASSET_TYPES = {AssetType.KEYWORD, AssetType.BRAND_NAME, AssetType.ORG_NAME}


def _normalize_domain(value: str) -> str:
    return value.strip().lower().lstrip(".").rstrip(".")


@dataclass
class AssetIndex:
    ip_lookup: dict[str, list[tuple[int, CustomerAsset]]] = field(default_factory=dict)
    cidr_networks: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, int, CustomerAsset]] = \
        field(default_factory=list)
    domain_records: list[tuple[str, int, CustomerAsset]] = field(default_factory=list)
    devices_by_vendor: dict[str, list[tuple[int, CustomerAsset]]] = field(default_factory=dict)
    cve_product_map: dict[str, list[CveProductMap]] = field(default_factory=dict)
    keyword_patterns: list[tuple[re.Pattern, int, CustomerAsset, str]] = field(default_factory=list)

    @classmethod
    async def build(cls, session: AsyncSession) -> "AssetIndex":
        idx = cls()

        assets_result = await session.execute(select(CustomerAsset))
        assets = assets_result.scalars().all()

        for asset in assets:
            customer_id = asset.customer_id
            asset_type = asset.asset_type
            value = (asset.asset_value or "").strip()

            if asset_type == AssetType.IP:
                key = value.lower()
                idx.ip_lookup.setdefault(key, []).append((customer_id, asset))

            elif asset_type == AssetType.CIDR:
                try:
                    network = ipaddress.ip_network(value, strict=False)
                    idx.cidr_networks.append((network, customer_id, asset))
                except ValueError:
                    logger.warning("Skipping unparseable CIDR asset id=%s value=%r", asset.id, value)

            elif asset_type in _DOMAIN_ASSET_TYPES:
                normalized = _normalize_domain(value)
                if normalized:
                    idx.domain_records.append((normalized, customer_id, asset))

            elif asset_type == AssetType.DEVICE:
                if asset.vendor:
                    vendor_key = asset.vendor.strip().lower()
                    idx.devices_by_vendor.setdefault(vendor_key, []).append((customer_id, asset))
                if asset.ip_address:
                    ip_key = asset.ip_address.strip().lower()
                    idx.ip_lookup.setdefault(ip_key, []).append((customer_id, asset))

            elif asset_type in _KEYWORD_ASSET_TYPES:
                if value:
                    pattern = re.compile(r"\b" + re.escape(value) + r"\b", re.IGNORECASE)
                    kind = "brand" if asset_type == AssetType.BRAND_NAME else "keyword"
                    idx.keyword_patterns.append((pattern, customer_id, asset, kind))

        cpm_result = await session.execute(select(CveProductMap))
        for row in cpm_result.scalars().all():
            idx.cve_product_map.setdefault(row.cve_id.upper(), []).append(row)

        logger.info(
            "AssetIndex built: ip=%d cidr=%d domain=%d device_vendors=%d "
            "cve_product_map=%d(cves) keyword_patterns=%d",
            len(idx.ip_lookup), len(idx.cidr_networks), len(idx.domain_records),
            len(idx.devices_by_vendor), len(idx.cve_product_map), len(idx.keyword_patterns),
        )
        return idx
