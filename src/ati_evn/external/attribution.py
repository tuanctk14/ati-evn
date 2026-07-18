"""Map an IP to a CustomerAsset via exact match or CIDR containment.

Fallback: create an "auto-discovered" CustomerAsset attributed to a
caller-designated customer, with discovery_source='censys'.
"""
from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ati_evn.db.models import AssetType, Customer, CustomerAsset
from ati_evn.db.query_utils import only_live_asset

logger = logging.getLogger("ati_evn.external.attribution")


async def attribute_ip(
    session: AsyncSession,
    ip: str,
    auto_discover_customer_id: int | None = None,
) -> tuple[int | None, int | None]:
    """Return (asset_id, customer_id) for the IP.

    Order:
      1. Exact match against CustomerAsset(asset_type=ip, asset_value=ip)
      2. CIDR containment: for each live asset with type=cidr, check if
         ip falls inside that CIDR
      3. If auto_discover_customer_id given: create a new asset
         asset_type=ip, asset_value=ip, discovery_source='censys'
      4. Otherwise: return (None, None) — orphan exposure
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        logger.warning("Invalid IP for attribution: %s", ip)
        return None, None

    stmt = select(CustomerAsset).where(
        CustomerAsset.asset_type == AssetType.IP,
        CustomerAsset.asset_value == ip,
        only_live_asset(),
    )
    exact = (await session.execute(stmt)).scalar_one_or_none()
    if exact:
        return exact.id, exact.customer_id

    stmt = select(CustomerAsset).where(
        CustomerAsset.asset_type == AssetType.CIDR,
        only_live_asset(),
    )
    cidr_rows = list((await session.execute(stmt)).scalars())
    for asset in cidr_rows:
        try:
            net = ipaddress.ip_network(asset.asset_value, strict=False)
            if ip_obj in net:
                return asset.id, asset.customer_id
        except ValueError:
            continue

    if auto_discover_customer_id:
        cust = await session.get(Customer, auto_discover_customer_id)
        if not cust or cust.deleted_at:
            logger.warning(
                "auto_discover_customer_id=%d invalid; skipping",
                auto_discover_customer_id,
            )
            return None, None
        new_asset = CustomerAsset(
            customer_id=auto_discover_customer_id,
            asset_type=AssetType.IP,
            asset_value=ip,
            discovery_source="censys",
            notes=f"Auto-discovered by Censys scan at {datetime.now(timezone.utc).isoformat()}",
            criticality="medium",
        )
        session.add(new_asset)
        await session.flush()
        logger.info(
            "Auto-discovered new asset #%d ip=%s for customer #%d",
            new_asset.id, ip, auto_discover_customer_id,
        )
        return new_asset.id, auto_discover_customer_id

    return None, None
