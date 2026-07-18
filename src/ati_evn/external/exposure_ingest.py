"""Persist normalized exposures. Upsert on (ip, port, service_name)."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select

from ati_evn.db.models import Exposure
from ati_evn.db.session import async_session
from ati_evn.external.attribution import attribute_ip

logger = logging.getLogger("ati_evn.external.exposure_ingest")


def _parse_censys_ts(value) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


async def upsert_exposures(
    exposures: list[dict],
    auto_discover_customer_id: int | None = None,
) -> dict:
    """Insert or update exposures. Return stats dict."""
    stats = {"new": 0, "updated": 0, "attributed": 0, "orphan": 0}
    now = datetime.now(timezone.utc)

    async with async_session() as session:
        for exp in exposures:
            ip = exp["ip"]
            port = exp["port"]
            svc = exp["service_name"]

            asset_id, customer_id = await attribute_ip(
                session, ip, auto_discover_customer_id
            )
            if asset_id:
                stats["attributed"] += 1
            else:
                stats["orphan"] += 1

            stmt = select(Exposure).where(
                Exposure.ip == ip,
                Exposure.port == port,
                Exposure.service_name == svc,
            )
            existing = (await session.execute(stmt)).scalar_one_or_none()
            last_seen_censys = _parse_censys_ts(exp.get("last_seen_censys"))

            if existing:
                existing.last_seen_local = now
                existing.status = "active"
                if last_seen_censys:
                    existing.last_seen_censys = last_seen_censys
                existing.product = exp.get("product") or existing.product
                existing.version = exp.get("version") or existing.version
                existing.vendor = exp.get("vendor") or existing.vendor
                existing.banner = exp.get("banner") or existing.banner
                existing.tls_enabled = exp.get("tls_enabled", existing.tls_enabled)
                existing.tls_version = exp.get("tls_version") or existing.tls_version
                existing.tls_expired = exp.get("tls_expired", existing.tls_expired)
                existing.tls_self_signed = exp.get(
                    "tls_self_signed", existing.tls_self_signed
                )
                existing.auth_required = exp.get("auth_required")
                existing.capabilities = exp.get("capabilities") or {}
                existing.censys_raw = exp.get("raw_service") or {}
                existing.asset_id = asset_id
                existing.customer_id = customer_id
                existing.asn = exp.get("asn")
                existing.asn_organization = exp.get("asn_organization")
                existing.country = exp.get("country")
                existing.updated_at = now
                stats["updated"] += 1
            else:
                row = Exposure(
                    ip=ip,
                    port=port,
                    service_name=svc,
                    transport=exp.get("transport"),
                    product=exp.get("product"),
                    version=exp.get("version"),
                    vendor=exp.get("vendor"),
                    banner=exp.get("banner"),
                    tls_enabled=exp.get("tls_enabled", False),
                    tls_version=exp.get("tls_version"),
                    tls_expired=exp.get("tls_expired", False),
                    tls_self_signed=exp.get("tls_self_signed", False),
                    auth_required=exp.get("auth_required"),
                    capabilities=exp.get("capabilities") or {},
                    asset_id=asset_id,
                    customer_id=customer_id,
                    asn=exp.get("asn"),
                    asn_organization=exp.get("asn_organization"),
                    country=exp.get("country"),
                    first_seen_censys=last_seen_censys,
                    last_seen_censys=last_seen_censys,
                    first_seen_local=now,
                    last_seen_local=now,
                    status="active",
                    censys_raw=exp.get("raw_service") or {},
                )
                session.add(row)
                stats["new"] += 1

        await session.commit()
    return stats
