"""Weekly Censys sweep — 3 IP assets max (quota-conscious).

Flow:
  1. Query CustomerAsset where asset_type=ip AND deleted_at IS NULL,
     limit 3.
  2. For each IP: search_ip + upsert_exposures.
  3. Collect touched exposure IDs.
  4. Process through rule engine + LLM vuln match -> Findings.
"""
from __future__ import annotations

import logging

from sqlalchemy import select

from ati_evn.db.models import AssetType, CustomerAsset, Exposure
from ati_evn.db.query_utils import only_live_asset
from ati_evn.db.session import async_session
from ati_evn.exposure_rules.finding_creator import process_exposures
from ati_evn.external.censys_client import CensysConfigError, CensysQuotaExceeded, search_ip
from ati_evn.external.exposure_ingest import upsert_exposures

logger = logging.getLogger("ati_evn.external.weekly_scan")

MAX_IP_PER_WEEK = 3


async def run_weekly_censys_scan() -> dict:
    """Public entry for scheduler. Returns stats dict."""
    logger.info("Starting weekly Censys IP sweep")
    stats = {
        "ips_scanned": 0, "exposures_new": 0, "exposures_updated": 0,
        "findings_created": 0, "indicators_created": 0, "errors": [],
    }

    async with async_session() as session:
        stmt = (
            select(CustomerAsset)
            .where(CustomerAsset.asset_type == AssetType.IP, only_live_asset())
            .order_by(CustomerAsset.id)
            .limit(MAX_IP_PER_WEEK)
        )
        assets = list((await session.execute(stmt)).scalars())

    if not assets:
        logger.info("No IP assets to scan")
        return stats

    all_exposure_ids: list[int] = []

    for asset in assets:
        try:
            logger.info("Scanning IP %s (asset #%d)", asset.asset_value, asset.id)
            exposures = await search_ip(asset.asset_value)
            if not exposures:
                stats["ips_scanned"] += 1
                continue
            upsert_stats = await upsert_exposures(exposures)
            stats["exposures_new"] += upsert_stats["new"]
            stats["exposures_updated"] += upsert_stats["updated"]

            async with async_session() as session:
                row = await session.execute(
                    select(Exposure.id).where(Exposure.ip == asset.asset_value)
                )
                all_exposure_ids.extend(r[0] for r in row)
            stats["ips_scanned"] += 1
        except CensysConfigError as e:
            stats["errors"].append(f"Config: {e}")
            logger.error("Weekly scan config error: %s", e)
            break
        except CensysQuotaExceeded as e:
            stats["errors"].append(f"Quota: {e}")
            logger.error("Weekly scan quota exceeded, stopping")
            break
        except Exception as e:
            stats["errors"].append(f"{asset.asset_value}: {e}")
            logger.exception("Scan failed for %s", asset.asset_value)
            continue

    if all_exposure_ids:
        proc_stats = await process_exposures(all_exposure_ids)
        # service_findings/config_findings actually create ThreatIndicator
        # rows (post slice 15A), only vuln_findings creates a real Finding
        # -- see finding_creator.process_exposures' docstring.
        stats["findings_created"] = proc_stats["vuln_findings"]
        stats["indicators_created"] = (
            proc_stats["service_findings"] + proc_stats["config_findings"]
        )
        stats["rule_engine"] = proc_stats

    logger.info("Weekly Censys sweep completed: %s", stats)
    return stats
