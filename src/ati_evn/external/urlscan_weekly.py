"""Weekly urlscan.io brand abuse scan -- 7 keyword/brand assets, Monday 05:00 UTC.

Iterates CustomerAsset(asset_type IN 'keyword', 'brand_name'). Cap
urlscan_max_results_per_query results per keyword (free tier ~5000/day,
comfortably wide for 7 keywords/week).
"""
from __future__ import annotations

import logging

from sqlalchemy import select

from ati_evn.config import get_settings
from ati_evn.db.models import AssetType, CustomerAsset
from ati_evn.db.query_utils import only_live_asset
from ati_evn.db.session import async_session
from ati_evn.external.brand_abuse_ingest import ingest_brand_abuse
from ati_evn.external.urlscan_client import UrlscanAPIError, UrlscanConfigError, search_brand

logger = logging.getLogger("ati_evn.external.urlscan_weekly")


async def run_weekly_urlscan_scan() -> dict:
    settings = get_settings()
    if not settings.urlscan_weekly_scan_enabled:
        logger.info("urlscan weekly scan disabled via config")
        return {"disabled": True}

    stats = {
        "keywords_scanned": 0, "sightings_new": 0, "sightings_updated": 0,
        "indicators_created": 0, "total_llm_calls": 0, "errors": [],
    }

    async with async_session() as session:
        stmt = (
            select(CustomerAsset)
            .where(
                CustomerAsset.asset_type.in_([AssetType.KEYWORD, AssetType.BRAND_NAME]),
                only_live_asset(),
            )
            .order_by(CustomerAsset.id)
        )
        assets = list((await session.execute(stmt)).scalars())

    if not assets:
        logger.info("No keyword/brand_name assets to scan")
        return stats

    logger.info(
        "Weekly urlscan: scanning %d keywords: %s",
        len(assets), [a.asset_value for a in assets],
    )

    for asset in assets:
        try:
            sightings = await search_brand(
                asset.asset_value, None, max_results=settings.urlscan_max_results_per_query,
            )
        except (UrlscanConfigError, UrlscanAPIError) as e:
            stats["errors"].append(f"{asset.asset_value}: {e}")
            logger.error("Weekly scan %s failed: %s", asset.asset_value, e)
            continue
        except Exception as e:
            stats["errors"].append(f"{asset.asset_value}: {e}")
            logger.exception("Weekly scan %s failed", asset.asset_value)
            continue

        if not sightings:
            stats["keywords_scanned"] += 1
            continue

        ingest = await ingest_brand_abuse(sightings)
        stats["sightings_new"] += ingest["new"]
        stats["sightings_updated"] += ingest["updated"]
        stats["indicators_created"] += ingest["indicators_created"]
        stats["total_llm_calls"] += ingest["llm_calls"]
        stats["keywords_scanned"] += 1

    logger.info("Weekly urlscan scan: %s", stats)
    return stats
