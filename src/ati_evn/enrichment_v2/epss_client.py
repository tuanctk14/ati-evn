"""FIRST.org EPSS API client.

Batch query: /data/v1/epss?cve=CVE-1,CVE-2,CVE-3
Free tier: no auth, generous limits. Cache TTL 24h (EPSS updated daily).
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from ati_evn.db.models import CveEnrichmentCache
from ati_evn.db.session import async_session

logger = logging.getLogger("ati_evn.enrichment_v2.epss_client")

URL = "https://api.first.org/data/v1/epss"
BATCH_SIZE = 100  # EPSS API accepts up to ~100 CVE per query


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(min=1, max=8),
    retry=retry_if_exception_type(httpx.RequestError),
    reraise=True,
)
async def _fetch_epss_batch(params: dict) -> httpx.Response:
    async with httpx.AsyncClient(timeout=15.0) as client:
        return await client.get(URL, params=params)


async def _cves_needing_epss(cve_ids: list[str]) -> list[str]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    async with async_session() as session:
        stmt = select(CveEnrichmentCache.cve_id).where(
            CveEnrichmentCache.cve_id.in_(cve_ids),
            CveEnrichmentCache.epss_score.is_not(None),
            CveEnrichmentCache.fetched_at >= cutoff,
        )
        fresh = {r[0] for r in await session.execute(stmt)}
    return [c for c in cve_ids if c not in fresh]


async def enrich_epss(cve_ids: list[str]) -> dict:
    """Batch-fetch EPSS for CVEs missing/stale in the cache."""
    cve_ids = list({c for c in cve_ids if c and c.startswith("CVE-")})
    if not cve_ids:
        return {"total": 0, "cached": 0, "fetched": 0, "errors": 0}

    needing = await _cves_needing_epss(cve_ids)
    stats = {
        "total": len(cve_ids), "cached": len(cve_ids) - len(needing),
        "fetched": 0, "errors": 0,
    }

    for i in range(0, len(needing), BATCH_SIZE):
        batch = needing[i:i + BATCH_SIZE]
        try:
            params = {"cve": ",".join(batch)}
            resp = await _fetch_epss_batch(params)
            if resp.status_code >= 400:
                logger.warning("EPSS HTTP %d for batch", resp.status_code)
                stats["errors"] += len(batch)
                continue
            data = resp.json()
        except Exception as e:
            logger.warning("EPSS batch fetch failed: %s", e)
            stats["errors"] += len(batch)
            continue

        results = data.get("data") or []
        now = datetime.now(timezone.utc)

        async with async_session() as session:
            for entry in results:
                cve_id = entry.get("cve")
                if not cve_id:
                    continue
                try:
                    score = float(entry.get("epss", 0))
                    percentile = float(entry.get("percentile", 0)) * 100
                except (TypeError, ValueError):
                    continue

                existing = await session.get(CveEnrichmentCache, cve_id)
                if existing:
                    existing.epss_score = score
                    existing.epss_percentile = percentile
                    existing.epss_date = entry.get("date")
                    existing.fetched_at = now
                else:
                    session.add(CveEnrichmentCache(
                        cve_id=cve_id,
                        is_kev=False,
                        epss_score=score,
                        epss_percentile=percentile,
                        epss_date=entry.get("date"),
                        fetched_at=now,
                    ))
                stats["fetched"] += 1

            await session.commit()

    logger.info("EPSS enrich: %s", stats)
    return stats
