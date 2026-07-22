"""Weekly GrayHatWarfare scan -- 7 keyword/brand assets, Sunday 04:00 UTC.

Iterates CustomerAsset(asset_type IN 'keyword', 'brand_name'). Cap 100
files per keyword. Total ~7 * 100 = 700 files max/week.
"""
from __future__ import annotations

import logging

from sqlalchemy import select

from ati_evn.config import get_settings
from ati_evn.db.models import AssetType, CustomerAsset
from ati_evn.db.query_utils import only_live_asset
from ati_evn.db.session import async_session
from ati_evn.external.document_ingest import ingest_documents
from ati_evn.external.grayhat_client import GrayhatAPIError, GrayhatConfigError, search_keyword

logger = logging.getLogger("ati_evn.external.grayhat_weekly")


async def run_weekly_grayhat_scan() -> dict:
    settings = get_settings()
    if not settings.grayhat_weekly_scan_enabled:
        logger.info("GrayHatWarfare weekly scan disabled via config")
        return {"disabled": True}

    stats = {
        "keywords_scanned": 0, "files_new": 0, "files_updated": 0,
        "findings_created": 0, "total_llm_calls": 0, "errors": [],
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
        "Weekly GrayHat: scanning %d keywords: %s",
        len(assets), [a.asset_value for a in assets],
    )

    for asset in assets:
        try:
            files = await search_keyword(asset.asset_value, max_files=settings.grayhat_max_files_per_keyword)
        except (GrayhatConfigError, GrayhatAPIError) as e:
            stats["errors"].append(f"{asset.asset_value}: {e}")
            logger.error("Weekly scan %s failed: %s", asset.asset_value, e)
            continue
        except Exception as e:
            stats["errors"].append(f"{asset.asset_value}: {e}")
            logger.exception("Weekly scan %s failed", asset.asset_value)
            continue

        if not files:
            stats["keywords_scanned"] += 1
            continue

        ingest = await ingest_documents(files)
        stats["files_new"] += ingest["new"]
        stats["files_updated"] += ingest["updated"]
        stats["findings_created"] += ingest["findings_created"]
        stats["total_llm_calls"] += ingest["llm_calls"]
        stats["keywords_scanned"] += 1

    logger.info("Weekly GrayHat scan: %s", stats)
    return stats
