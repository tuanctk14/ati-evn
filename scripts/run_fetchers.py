"""Run all configured fetchers sequentially and ingest results into the DB.

Usage:
    docker compose up -d postgres
    python scripts/init_db.py
    python scripts/run_fetchers.py
"""
from __future__ import annotations

import asyncio
import logging
import sys
import time

from sqlalchemy import text

from ati_evn.db.session import async_session
from ati_evn.fetchers.base import IOCFetcher, RawIOC
from ati_evn.fetchers.cve.nvd import NVDFetcher
from ati_evn.fetchers.ioc.feodo import FeodoFetcher
from ati_evn.fetchers.ioc.malwarebazaar import MalwareBazaarFetcher
from ati_evn.fetchers.ioc.threatfox import ThreatFoxFetcher
from ati_evn.fetchers.ioc.urlhaus import URLhausFetcher
from ati_evn.ingest.pipeline import IngestStats, ingest_raw_iocs

logger = logging.getLogger("ati_evn.run_fetchers")

FETCHERS: list[IOCFetcher] = [
    ThreatFoxFetcher(),
    MalwareBazaarFetcher(),
    FeodoFetcher(),
    URLhausFetcher(),
    NVDFetcher(),
]

# NVD needs a wider lastMod window than the other feeds — CPE data is
# attached by analysts days after publish, so 24h of pubStart yields almost
# no product mappings. See fetchers/cve/nvd.py docstring for detail.
SINCE_HOURS_OVERRIDES: dict[str, int] = {
    "nvd": 48,
}


async def _run_one(fetcher: IOCFetcher, since_hours: int) -> tuple[list[RawIOC], list[dict], float, str | None]:
    started = time.perf_counter()
    error: str | None = None
    raw_iocs: list[RawIOC] = []
    product_rows: list[dict] = []

    try:
        result = await fetcher.fetch(since_hours=since_hours)
        if isinstance(result, tuple):
            raw_iocs, product_rows = result
        else:
            raw_iocs = result
    except Exception as e:  # noqa: BLE001 — runner must never crash on a fetcher bug
        error = str(e)
        logger.exception("Fetcher %s raised an uncaught exception", fetcher.name)

    duration_ms = (time.perf_counter() - started) * 1000
    return raw_iocs, product_rows, duration_ms, error


async def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )

    rows: list[dict] = []
    grand_total = IngestStats()

    async with async_session() as session:
        for fetcher in FETCHERS:
            if not fetcher.is_configured():
                logger.warning("Skipping %s — not configured (missing API key)", fetcher.name)
                rows.append({
                    "fetcher": fetcher.name, "fetched": 0, "inserted": 0,
                    "deduped": 0, "rejected": 0, "duration_ms": 0.0, "note": "skipped (not configured)",
                })
                continue

            since_hours = SINCE_HOURS_OVERRIDES.get(fetcher.name, 24)
            raw_iocs, product_rows, duration_ms, error = await _run_one(fetcher, since_hours=since_hours)

            if error:
                rows.append({
                    "fetcher": fetcher.name, "fetched": 0, "inserted": 0,
                    "deduped": 0, "rejected": 0, "duration_ms": duration_ms, "note": f"error: {error}",
                })
                continue

            stats = await ingest_raw_iocs(
                session,
                raw_iocs,
                dedup_window_hours=24,
                cve_product_map_rows=product_rows,
            )
            grand_total.merge(stats)

            rows.append({
                "fetcher": fetcher.name,
                "fetched": len(raw_iocs),
                "inserted": stats.inserted,
                "deduped": stats.deduped,
                "rejected": stats.rejected,
                "duration_ms": round(duration_ms, 1),
                "note": f"+{len(product_rows)} cve_product_map rows" if product_rows else "",
            })

    # ── Print table ──────────────────────────────────────────────────────────
    header = f"{'fetcher':15s} {'fetched':>8s} {'inserted':>8s} {'deduped':>8s} {'rejected':>8s} {'ms':>8s}  note"
    print(header)
    print("-" * len(header))
    for r in rows:
        print(
            f"{r['fetcher']:15s} {r['fetched']:8d} {r['inserted']:8d} "
            f"{r['deduped']:8d} {r['rejected']:8d} {r['duration_ms']:8.1f}  {r['note']}"
        )

    print()
    print(f"Grand totals: inserted={grand_total.inserted} deduped={grand_total.deduped} "
          f"rejected={grand_total.rejected}")
    print(f"By source   : {grand_total.by_source}")
    print(f"By ioc_type : {grand_total.by_ioc_type}")

    # ── DB verification queries ─────────────────────────────────────────────
    async with async_session() as session:
        detections_total = (await session.execute(text("SELECT count(*) FROM detections"))).scalar_one()
        detections_by_source = (await session.execute(
            text("SELECT source, count(*) FROM detections GROUP BY source ORDER BY count(*) DESC")
        )).all()
        cpm_total = (await session.execute(text("SELECT count(*) FROM cve_product_map"))).scalar_one()
        cpm_by_source = (await session.execute(
            text("SELECT source, count(*) FROM cve_product_map GROUP BY source ORDER BY count(*) DESC")
        )).all()

    print()
    print(f"DB detections total      : {detections_total}")
    print(f"DB detections by source  : {dict(detections_by_source)}")
    print(f"DB cve_product_map total : {cpm_total}")
    print(f"DB cve_product_map by src: {dict(cpm_by_source)}")

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
