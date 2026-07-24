"""Batch backfill for existing Findings + Exposures.

Discovery: IPs from Finding.ioc_type=ipv4/ipv6 + Exposure.ip (active status).
Filter: skip IPs already enriched within cache TTL.
Batch: enrichment_batch_size IPs per run (config, default 50).

Note: Finding has no deleted_at column (soft-delete isn't part of this
model) -- only Exposure carries a status column, filtered to 'active'.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from ati_evn.config import get_settings
from ati_evn.db.models import Exposure, Finding, IpEnrichment
from ati_evn.db.session import async_session
from ati_evn.enrichment_v2.aggregator import compute_and_store
from ati_evn.enrichment_v2.config import get_background_providers, get_foreground_providers, get_ttl_hours
from ati_evn.enrichment_v2.ip_enricher import enrich_batch, enrich_ip_provider

logger = logging.getLogger("ati_evn.enrichment_v2.backfill")

BACKFILL_IPS_PER_TICK = 10  # 10 IP x 5 provider = 50 API calls/tick


async def _discover_ips_to_enrich(limit: int) -> list[str]:
    """Return list of IPs (unique) needing enrichment.

    Priority order:
      1. Findings with ioc_type ipv4/ipv6 (customer-attributed)
      2. Exposures with status='active' (from Censys)
      3. Skip IPs enriched within cache_hours
    """
    settings = get_settings()
    cutoff = datetime.now(timezone.utc) - timedelta(hours=settings.enrichment_cache_hours)

    async with async_session() as session:
        recent_stmt = select(IpEnrichment.ip).where(
            IpEnrichment.provider == "abuseipdb",
            IpEnrichment.queried_at >= cutoff,
        )
        recently_enriched = {r[0] for r in await session.execute(recent_stmt)}

        candidates: list[str] = []
        finding_stmt = select(Finding.ioc_value).where(
            Finding.ioc_type.in_(["ipv4", "ipv6"]),
        ).distinct()
        for r in await session.execute(finding_stmt):
            ip = r[0]
            if ip and ip not in recently_enriched:
                candidates.append(ip)
                if len(candidates) >= limit:
                    return candidates

        exp_stmt = select(Exposure.ip).where(Exposure.status == "active").distinct()
        for r in await session.execute(exp_stmt):
            ip = r[0]
            if ip and ip not in recently_enriched and ip not in candidates:
                candidates.append(ip)
                if len(candidates) >= limit:
                    break

        return candidates


async def run_backfill_batch() -> dict:
    """One tick of the backfill scheduler. Returns stats dict."""
    settings = get_settings()
    if not settings.enrichment_scheduler_enabled:
        return {"disabled": True}

    batch_size = settings.enrichment_batch_size
    ips = await _discover_ips_to_enrich(batch_size)

    if not ips:
        logger.info("No IPs need enrichment in this tick")
        return {"total": 0, "cached": 0, "fresh": 0, "errors": 0, "discovered": 0}

    logger.info("Enrichment backfill tick: %d IPs to check (batch_size=%d)", len(ips), batch_size)

    stats = await enrich_batch(ips)
    stats["discovered"] = len(ips)
    logger.info("Backfill tick complete: %s", stats)
    return stats


# ── Slice 13B: multi-provider backfill (replaces the AbuseIPDB-only tick
# above as the scheduled job; run_backfill_batch is kept for direct callers
# and tests that still want the slice-12 single-provider behavior). ────────

async def _all_providers_recent(ip: str, providers: list[str]) -> bool:
    """Check if all listed providers have recent (within their own TTL)
    enrichment for this IP."""
    async with async_session() as session:
        for p in providers:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=get_ttl_hours(p))
            r = await session.execute(
                select(IpEnrichment.id).where(
                    IpEnrichment.ip == ip,
                    IpEnrichment.provider == p,
                    IpEnrichment.queried_at >= cutoff,
                ).limit(1)
            )
            if not r.scalar_one_or_none():
                return False
    return True


async def _discover_ips_needing_backfill(limit: int) -> list[str]:
    """Return IPs where AT LEAST ONE enabled provider is stale/missing.

    Note: Finding has no deleted_at column (soft-delete isn't part of
    this model) -- only Exposure carries a status column, filtered to
    'active', same as _discover_ips_to_enrich above.
    """
    all_providers = get_foreground_providers() + get_background_providers()

    async with async_session() as session:
        candidates: set[str] = set()

        f_stmt = select(Finding.ioc_value).where(
            Finding.ioc_type.in_(["ipv4", "ipv6"]),
        ).distinct()
        for r in await session.execute(f_stmt):
            if r[0]:
                candidates.add(r[0])

        e_stmt = select(Exposure.ip).where(Exposure.status == "active").distinct()
        for r in await session.execute(e_stmt):
            if r[0]:
                candidates.add(r[0])

    need_enrichment = []
    for ip in sorted(candidates):
        if len(need_enrichment) >= limit:
            break
        if not await _all_providers_recent(ip, all_providers):
            need_enrichment.append(ip)

    return need_enrichment


async def run_backfill_batch_multi() -> dict:
    """Multi-provider backfill tick.

    For each IP: enrich every enabled provider whose cache is stale,
    then compute the aggregate ONCE after all providers are done
    (Q1 backfill-recompute-per-IP design).
    """
    settings = get_settings()
    if not settings.enrichment_scheduler_enabled:
        return {"disabled": True}

    all_providers = get_foreground_providers() + get_background_providers()
    ips = await _discover_ips_needing_backfill(BACKFILL_IPS_PER_TICK)

    if not ips:
        logger.info("Multi-provider backfill: no IPs need enrichment")
        return {
            "ips_processed": 0, "providers_called": 0,
            "cached": 0, "fresh": 0, "errors": 0, "aggregates_updated": 0,
        }

    stats = {
        "ips_processed": 0, "providers_called": 0,
        "cached": 0, "fresh": 0, "errors": 0,
        "aggregates_updated": 0, "quota_exceeded_providers": [],
    }

    for ip in ips:
        for provider in all_providers:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=get_ttl_hours(provider))
            async with async_session() as session:
                r = await session.execute(
                    select(IpEnrichment.id).where(
                        IpEnrichment.ip == ip,
                        IpEnrichment.provider == provider,
                        IpEnrichment.queried_at >= cutoff,
                        IpEnrichment.error_message.is_(None),
                    ).limit(1)
                )
                if r.scalar_one_or_none():
                    stats["cached"] += 1
                    continue

            row, status = await enrich_ip_provider(ip, provider)
            stats["providers_called"] += 1
            if status == "fresh":
                stats["fresh"] += 1
            elif status == "cached":
                stats["cached"] += 1
            else:
                stats["errors"] += 1
                if row and "rate limit" in (row.error_message or "").lower():
                    if provider not in stats["quota_exceeded_providers"]:
                        stats["quota_exceeded_providers"].append(provider)

        agg = await compute_and_store(ip)
        if agg:
            stats["aggregates_updated"] += 1
        stats["ips_processed"] += 1

    logger.info("Multi-provider backfill tick: %s", stats)
    return stats
