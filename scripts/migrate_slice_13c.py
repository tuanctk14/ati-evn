"""One-time migration: recompute IpEnrichment scores from stored raw data
after the slice 13C adapter/ScoringEngine split.

Idempotent -- safe to re-run (rows already migrated carry data.signals
and are used as-is instead of re-derived from pre-13C raw_data shape).
"""
from __future__ import annotations

import asyncio
import logging

from sqlalchemy import select

from ati_evn.db.models import IpEnrichment
from ati_evn.db.session import async_session
from ati_evn.enrichment_v2.adapters._base import ProviderSignal
from ati_evn.enrichment_v2.aggregator import compute_and_store
from ati_evn.enrichment_v2.scoring import score_from_signal

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("migrate_13c")


def _extract_signals_from_raw(provider: str, data: dict) -> dict:
    """Re-derive signals from raw_data. Different logic per provider
    because pre-13C raw_data schema is provider-specific.

    For rows already migrated (have data.signals), use that.
    """
    if data.get("signals"):
        return data["signals"]

    if provider == "abuseipdb":
        return {
            "abuse_confidence": int(data.get("abuse_confidence") or 0),
            "total_reports": int(data.get("total_reports") or 0),
            "usage_type": data.get("usage_type"),
            "is_tor": bool(data.get("is_tor")),
            "hostnames": data.get("hostnames") or [],
            "domain": data.get("domain"),
            "last_reported": data.get("last_reported"),
        }
    elif provider == "virustotal":
        return {
            "malicious_engines": int(data.get("malicious_engines") or 0),
            "suspicious_engines": int(data.get("suspicious_engines") or 0),
            "harmless_engines": int(data.get("harmless_engines") or 0),
            "undetected_engines": int(data.get("undetected_engines") or 0),
            "total_engines": int(data.get("total_engines") or 0),
            "reputation": data.get("reputation"),
            "asn": data.get("asn"),
            "tags": data.get("tags") or [],
        }
    elif provider == "otx":
        return {
            "pulse_count": int(data.get("pulse_count") or 0),
            "pulses": data.get("pulses") or [],
            "reputation": data.get("reputation") or 0,
            "asn": data.get("asn"),
        }
    elif provider == "pulsedive":
        threats = data.get("threats") or []
        feeds = data.get("feeds") or []
        return {
            "risk_level": (data.get("risk") or "unknown").lower(),
            "threat_count": len(threats),
            "feed_count": len(feeds),
            "threats": threats,
            "feeds": feeds,
        }
    elif provider == "leakix":
        from ati_evn.enrichment_v2.config import get_provider_config
        cfg = get_provider_config("leakix")
        malicious_types = set(
            (t or "").lower() for t in (cfg.get("malicious_event_types") or [])
        )
        event_types = data.get("event_types") or []
        mtc = sum(1 for e in event_types if (e or "").lower() in malicious_types)
        return {
            "services_count": int(data.get("services_count") or 0),
            "leaks_count": int(data.get("leaks_count") or 0),
            "event_types": event_types,
            "malicious_event_types_count": mtc,
        }
    return {}


async def main() -> None:
    async with async_session() as session:
        rows = list((await session.execute(select(IpEnrichment))).scalars())

    logger.info("Migrating %d IpEnrichment rows", len(rows))

    migrated = 0
    skipped_errors = 0
    ips_touched: set[str] = set()

    for row in rows:
        if row.error_message:
            skipped_errors += 1
            continue

        signals = _extract_signals_from_raw(row.provider, row.data or {})

        signal = ProviderSignal(
            provider=row.provider,
            signals=signals,
            country=row.country,
            isp=row.isp,
            raw_data=row.data or {},
        )

        verdict_obj = score_from_signal(signal)

        async with async_session() as s:
            db_row = await s.get(IpEnrichment, row.id)
            if not db_row:
                continue
            db_row.risk_score = verdict_obj.normalized_score
            db_row.verdict = verdict_obj.verdict
            db_row.verdict_confidence = verdict_obj.confidence
            db_row.is_malicious = verdict_obj.verdict == "malicious"
            new_data = dict(row.data or {})
            new_data["signals"] = verdict_obj.signals
            db_row.data = new_data
            await s.commit()

        migrated += 1
        ips_touched.add(row.ip)

    logger.info("Migrated %d rows, skipped %d error rows", migrated, skipped_errors)
    logger.info("Recomputing %d aggregate rows", len(ips_touched))

    for ip in ips_touched:
        await compute_and_store(ip)

    logger.info("Migration complete")


if __name__ == "__main__":
    asyncio.run(main())
