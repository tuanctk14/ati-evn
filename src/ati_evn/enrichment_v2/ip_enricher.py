"""IP enrichment orchestrator.

Slice 13A: refactored to the adapter pattern (enrichment_v2/adapters/).
enrich_ip_provider is the generic entry point for any registered
provider; enrich_ip_abuseipdb / enrich_batch are kept as slice 12
backward-compat aliases so the existing backfill scheduler keeps
working unchanged.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from ati_evn.db.models import IpAggregatedScore, IpEnrichment
from ati_evn.db.session import async_session
from ati_evn.enrichment_v2.adapters.registry import get_adapter
from ati_evn.enrichment_v2.aggregator import compute_and_store
from ati_evn.enrichment_v2.config import get_background_providers, get_foreground_providers, get_ttl_hours

logger = logging.getLogger("ati_evn.enrichment_v2.ip_enricher")


async def get_cached_enrichment(ip: str, provider: str) -> IpEnrichment | None:
    """Return cached enrichment if within the provider's TTL. None if stale/missing."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=get_ttl_hours(provider))

    async with async_session() as session:
        row = await session.execute(
            select(IpEnrichment).where(
                IpEnrichment.ip == ip,
                IpEnrichment.provider == provider,
                IpEnrichment.queried_at >= cutoff,
                IpEnrichment.error_message.is_(None),
            ).limit(1)
        )
        return row.scalar_one_or_none()


async def enrich_ip_provider(ip: str, provider: str, force: bool = False) -> tuple[IpEnrichment | None, str]:
    """Enrich IP via specific provider using its adapter. Returns (row, status).

    status: 'cached' | 'fresh' | 'error'
    """
    if not force:
        cached = await get_cached_enrichment(ip, provider)
        if cached:
            return cached, "cached"

    adapter = get_adapter(provider)
    verdict = await adapter.fetch(ip)

    now = datetime.now(timezone.utc)
    async with async_session() as session:
        stmt = select(IpEnrichment).where(IpEnrichment.ip == ip, IpEnrichment.provider == provider)
        existing = (await session.execute(stmt)).scalar_one_or_none()

        data_dict = {
            "ip": ip,
            "provider": provider,
            "risk_score": verdict.normalized_score,
            "country": verdict.country,
            "isp": verdict.isp,
            "is_malicious": verdict.verdict == "malicious",
            "verdict": verdict.verdict,
            "verdict_confidence": verdict.confidence,
            "data": verdict.raw_data,
            "queried_at": now,
            "error_message": verdict.error,
        }

        if existing:
            for k, v in data_dict.items():
                if k not in ("ip", "provider"):
                    setattr(existing, k, v)
            row = existing
        else:
            row = IpEnrichment(**data_dict)
            session.add(row)
        await session.commit()
        await session.refresh(row)

    status = "error" if verdict.error else "fresh"
    return row, status


async def enrich_batch_provider(ips: list[str], provider: str) -> dict:
    """Enrich batch of IPs via a specific provider. Return stats dict."""
    stats = {"total": len(ips), "cached": 0, "fresh": 0, "errors": 0, "provider": provider}
    for ip in ips:
        row, status = await enrich_ip_provider(ip, provider)
        if status == "cached":
            stats["cached"] += 1
        elif status == "fresh":
            stats["fresh"] += 1
        else:
            stats["errors"] += 1
    return stats


async def _enrich_ip_providers(ip: str, providers: list[str], force: bool) -> tuple[list[dict], IpAggregatedScore | None]:
    """Run `providers` sequentially for one IP, recomputing the aggregate
    after each provider (Q1 interactive-recompute-per-provider design)."""
    results = []
    for provider in providers:
        row, status = await enrich_ip_provider(ip, provider, force=force)
        results.append({
            "provider": provider, "status": status,
            "verdict": row.verdict if row else None,
            "score": row.risk_score if row else None,
            "error": row.error_message if row else None,
        })
        await compute_and_store(ip)

    agg = await compute_and_store(ip)
    return results, agg


async def enrich_ip_foreground(ip: str, force: bool = False) -> tuple[list[dict], IpAggregatedScore | None]:
    """Run foreground providers (fast, for interactive /enrich_ip).

    Sequential: aggregate recomputes after EACH provider.
    Returns (per_provider_results, aggregate_row).
    """
    return await _enrich_ip_providers(ip, get_foreground_providers(), force)


async def enrich_ip_full(ip: str, force: bool = False) -> tuple[list[dict], IpAggregatedScore | None]:
    """Run ALL providers (foreground + background). Used by --full flag.

    Sequential per-provider, recompute after each.
    """
    all_providers = get_foreground_providers() + get_background_providers()
    return await _enrich_ip_providers(ip, all_providers, force)


# ── Slice 12 backward-compat aliases ────────────────────────────────────────
# The slice 12 backfill scheduler (enrichment_v2/backfill.py) calls these
# two names directly; keeping them working unchanged avoids a breaking
# change while every other caller can move to the generic functions above.

async def enrich_ip_abuseipdb(ip: str, force: bool = False) -> tuple[IpEnrichment | None, str]:
    row, status = await enrich_ip_provider(ip, "abuseipdb", force=force)
    if status == "error":
        msg = row.error_message if row else "unknown error"
        # slice 12 callers (telegram/commands/enrich_ip.py) branch on these
        # exact prefixes -- preserve them so the UI still shows the right message.
        if "missing" in msg:
            return None, f"config_error: {msg}"
        if "Rate limited" in msg:
            return None, "quota_exceeded"
        return None, f"api_error: {msg}"
    return row, status


async def enrich_batch(ips: list[str]) -> dict:
    """Slice 12 alias: AbuseIPDB-only batch enrich."""
    stats = await enrich_batch_provider(ips, "abuseipdb")
    stats["quota_exceeded"] = False
    return stats
