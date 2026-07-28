"""Migrate non-CVE Findings -> ThreatIndicators (slice 15A).

Idempotent: safe to re-run. Uses metadata['migrated_to_ti_id'] on
Finding to track migration state.

Steps:
1. Identify Findings with ioc_type != 'cve_id'
2. For each, insert corresponding ThreatIndicator
3. Update AlertQueue rows: swap finding_id -> threat_indicator_id
4. Update Alert rows: same
5. Soft-mark migrated Finding (metadata only) -- do NOT delete, retain
   for historical trace

Real metadata key names (verified against live DB, not assumed):
  exposed_document Finding -> metadata['document_id']
  brand_abuse Finding       -> metadata['brand_abuse_id']
  exposure Finding          -> metadata['exposure_id']
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import select, update

from ati_evn.db.models import Alert, AlertQueue, Finding, ThreatIndicator
from ati_evn.db.session import async_session
from ati_evn.db.threat_indicator_ttl import compute_expires_at

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("migrate_15a")

IOC_TYPE_MAP = {
    "ipv4": "ipv4", "ipv6": "ipv6",
    "domain": "domain", "url": "url",
    "sha256": "sha256", "sha1": "sha1", "md5": "md5",
    "brand_abuse": "brand_abuse",
    "exposed_document": "exposed_document",
    "exposure": "exposure",
    # cve_id: NOT migrated -- stays in Finding.
}


def _map_source_entity(finding: Finding) -> tuple[str | None, int | None]:
    meta = finding.metadata_ or {}
    if "document_id" in meta:
        return "exposed_document", meta["document_id"]
    if "brand_abuse_id" in meta:
        return "brand_abuse_sighting", meta["brand_abuse_id"]
    if "exposure_id" in meta:
        return "exposure", meta["exposure_id"]
    return None, None


async def main() -> dict:
    stats = {
        "eligible_findings": 0,
        "already_migrated": 0,
        "migrated": 0,
        "alert_queue_swapped": 0,
        "alert_swapped": 0,
        "errors": 0,
    }

    async with async_session() as session:
        stmt = select(Finding).where(Finding.ioc_type != "cve_id")
        candidates = list((await session.execute(stmt)).scalars())
        stats["eligible_findings"] = len(candidates)

    logger.info("Found %d non-CVE findings to migrate", stats["eligible_findings"])

    for f in candidates:
        meta = f.metadata_ or {}
        if meta.get("migrated_to_ti_id"):
            stats["already_migrated"] += 1
            continue

        mapped_type = IOC_TYPE_MAP.get(f.ioc_type)
        if not mapped_type:
            logger.warning("Unknown ioc_type '%s' for finding #%d, skip", f.ioc_type, f.id)
            stats["errors"] += 1
            continue

        try:
            src_entity_type, src_entity_id = _map_source_entity(f)
            first_seen = f.first_seen or datetime.now(timezone.utc)
            expires = compute_expires_at(mapped_type, first_seen)

            async with async_session() as s:
                ti = ThreatIndicator(
                    indicator_type=mapped_type,
                    indicator_value=(f.ioc_value or "")[:2000],
                    source_entity_type=src_entity_type,
                    source_entity_id=src_entity_id,
                    customer_id=f.customer_id,
                    matched_asset_id=None,
                    matched_asset_value=(f.matched_asset or "")[:300],
                    source=(f.sources[0] if f.sources else "unknown")[:60],
                    sources=list(f.sources or []),
                    source_count=f.source_count or 1,
                    title=f.title[:500],
                    detection_reason=f.detection_reason,
                    severity=f.severity,
                    status="active",
                    first_seen=first_seen,
                    last_seen=f.last_seen or first_seen,
                    expires_at=expires,
                    metadata_={
                        **(f.metadata_ or {}),
                        "_migrated_from_finding": f.id,
                        "_migrated_at": datetime.now(timezone.utc).isoformat(),
                    },
                )
                s.add(ti)
                await s.flush()
                ti_id = ti.id

                aq_result = await s.execute(
                    update(AlertQueue)
                    .where(AlertQueue.finding_id == f.id)
                    .values(finding_id=None, threat_indicator_id=ti_id)
                    .returning(AlertQueue.id)
                )
                stats["alert_queue_swapped"] += len(list(aq_result))

                al_result = await s.execute(
                    update(Alert)
                    .where(Alert.finding_id == f.id)
                    .values(finding_id=None, threat_indicator_id=ti_id)
                    .returning(Alert.id)
                )
                stats["alert_swapped"] += len(list(al_result))

                finding_meta = dict(f.metadata_ or {})
                finding_meta["migrated_to_ti_id"] = ti_id
                finding_meta["migrated_at"] = datetime.now(timezone.utc).isoformat()
                await s.execute(
                    update(Finding).where(Finding.id == f.id).values(metadata_=finding_meta)
                )

                await s.commit()
                stats["migrated"] += 1

        except Exception:
            logger.exception("Migration failed for finding #%d", f.id)
            stats["errors"] += 1

    logger.info("Migration stats: %s", stats)
    return stats


if __name__ == "__main__":
    asyncio.run(main())
