"""CISA KEV JSON feed downloader.

Downloads the single-file catalog, upserts is_kev flag + KEV metadata
for each CVE. Refresh every 24h (idempotent -- safe to call from report
generation without a pre-check).
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from ati_evn.db.models import CveEnrichmentCache
from ati_evn.db.session import async_session

logger = logging.getLogger("ati_evn.enrichment_v2.kev_client")

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REFRESH_TTL_HOURS = 24


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(min=1, max=8),
    retry=retry_if_exception_type(httpx.RequestError),
    reraise=True,
)
async def _fetch_kev_catalog() -> httpx.Response:
    async with httpx.AsyncClient(timeout=30.0) as client:
        return await client.get(URL)


async def _feed_needs_refresh() -> bool:
    """Check if any KEV row is fresher than TTL (proxy for feed staleness)."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=REFRESH_TTL_HOURS)
    async with async_session() as session:
        r = await session.execute(
            select(CveEnrichmentCache).where(
                CveEnrichmentCache.is_kev.is_(True),
                CveEnrichmentCache.fetched_at >= cutoff,
            ).limit(1)
        )
        if r.scalar_one_or_none():
            return False
    return True


async def refresh_kev_catalog() -> dict:
    """Download KEV JSON + upsert flag + metadata for all listed CVEs."""
    if not await _feed_needs_refresh():
        logger.debug("KEV feed fresh (< %dh), skipping refresh", REFRESH_TTL_HOURS)
        return {"skipped": True, "reason": "cache_fresh"}

    try:
        resp = await _fetch_kev_catalog()
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        logger.error("KEV download failed: %s", e)
        return {"error": str(e)[:200]}

    vulnerabilities = data.get("vulnerabilities") or []
    now = datetime.now(timezone.utc)
    updated = 0

    async with async_session() as session:
        for entry in vulnerabilities:
            cve_id = entry.get("cveID")
            if not cve_id:
                continue

            existing = await session.get(CveEnrichmentCache, cve_id)
            fields = {
                "is_kev": True,
                "kev_date_added": entry.get("dateAdded"),
                "kev_vendor": (entry.get("vendorProject") or "")[:200],
                "kev_product": (entry.get("product") or "")[:200],
                "kev_short_description": entry.get("shortDescription"),
                "kev_required_action": entry.get("requiredAction"),
                "kev_due_date": entry.get("dueDate"),
                "fetched_at": now,
                "fetch_error": None,
            }
            if existing:
                for k, v in fields.items():
                    setattr(existing, k, v)
            else:
                session.add(CveEnrichmentCache(cve_id=cve_id, **fields))
            updated += 1

        await session.commit()

    logger.info("KEV refresh: %d CVE updated", updated)
    return {
        "cve_count": len(vulnerabilities),
        "upserted": updated,
        "catalog_version": data.get("catalogVersion"),
        "date_released": data.get("dateReleased"),
    }
