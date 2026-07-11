"""Rescan pipeline. Called after an analyst adds a new asset (or manually via
scripts/rescan.py).

Two phases:
1. LLM inference for CVE detections newly eligible — CVEs with no CPE data
   that were previously skipped by the filter because none of EVN's asset
   vendors appeared in scope, but now do (either because a new vendor was
   just added, or --focus-vendor narrows straight to it).
2. Deterministic matcher pass over Detection.status='unmatched' — the CVEs
   that failed to match under the OLD asset set get a fresh look against
   the new one, plus anything the LLM phase just filled in.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass

from sqlalchemy import text

from ati_evn.config import get_settings
from ati_evn.db.models import DetectionStatus
from ati_evn.db.queries import load_evn_vendors_lowercase
from ati_evn.db.session import async_session
from ati_evn.ingest.pipeline import upsert_cve_cwe_map, upsert_cve_product_map
from ati_evn.llm.client import LLMClient
from ati_evn.llm.cpe_inferrer import infer_missing_metadata
from ati_evn.llm.cve_filter import should_run_llm
from ati_evn.match.customer_router import RouteStats, route_detections

logger = logging.getLogger("ati_evn.rescan")

CANDIDATE_QUERY = text("""
    SELECT d.ioc_value AS cve_id, d.raw_text AS description,
           d.metadata->'references' AS refs
    FROM detections d
    WHERE d.ioc_type = 'cve_id'
      AND d.status = 'UNMATCHED'
      AND NOT EXISTS (
        SELECT 1 FROM cve_product_map cpm
        WHERE cpm.cve_id = d.ioc_value
      )
""")


@dataclass
class RescanStats:
    candidate_cves_for_llm: int
    llm_calls: int
    llm_extracted: int
    matcher: RouteStats
    elapsed_seconds: float


async def run_rescan_sync(reason: str, focus_vendor: str | None = None) -> RescanStats:
    """Run the two-phase rescan synchronously (awaited to completion).
    Safe to call from a CLI script or as a background asyncio.Task."""
    start = time.monotonic()
    settings = get_settings()
    logger.info("Rescan starting: reason=%r focus_vendor=%r", reason, focus_vendor)

    async with async_session() as session:
        evn_vendors = await load_evn_vendors_lowercase(session)
        hint_set = {focus_vendor.lower()} if focus_vendor else evn_vendors

        rows = (await session.execute(CANDIDATE_QUERY)).mappings().all()

        eligible = []
        for row in rows:
            should, _reason = should_run_llm(
                has_cpe=False, has_cwe=False,  # by construction: no CPE row exists yet
                description=row["description"] or "",
                references=row["refs"] or [],
                evn_vendors=hint_set,
            )
            if should:
                eligible.append(row)

        logger.info("Rescan: %d candidate CVEs, %d eligible after vendor filter",
                    len(rows), len(eligible))

        llm_calls = 0
        extracted_cpe_rows: list[dict] = []
        extracted_cwe_rows: list[dict] = []

        if eligible and settings.openai_api_key:
            client = LLMClient(settings)
            sem = asyncio.Semaphore(settings.llm_max_concurrent)

            async def _one(row):
                nonlocal llm_calls
                async with sem:
                    try:
                        meta = await infer_missing_metadata(
                            client, row["cve_id"], row["description"] or "", row["refs"] or [],
                            need_cpe=True, need_cwe=True,
                            context_hint_vendors=list(evn_vendors),
                        )
                        llm_calls += 1
                        return meta
                    except Exception as e:  # noqa: BLE001 — one bad CVE shouldn't kill the rescan
                        logger.warning("Rescan LLM failed for %s: %s", row["cve_id"], e)
                        return None

            metas = await asyncio.gather(*[_one(r) for r in eligible])
            for row, meta in zip(eligible, metas):
                if not meta:
                    continue
                for e in meta.cpe_entries:
                    if e.confidence >= settings.llm_cpe_min_confidence:
                        extracted_cpe_rows.append({
                            "cve_id": row["cve_id"], "vendor": e.vendor, "product": e.product,
                            "version_range": e.version_range, "source": "llm_inferred",
                            "confidence": e.confidence, "reasoning": e.reasoning,
                        })
                for c in meta.cwe_ids:
                    extracted_cwe_rows.append({
                        "cve_id": row["cve_id"], "cwe_id": c, "source": "llm_inferred",
                        "confidence": 0.7, "reasoning": meta.reasoning,
                    })

            await upsert_cve_product_map(session, extracted_cpe_rows)
            await upsert_cve_cwe_map(session, extracted_cwe_rows)
            await session.commit()

        matcher_stats = await route_detections(session, only_status=DetectionStatus.UNMATCHED)

    elapsed = time.monotonic() - start
    stats = RescanStats(
        candidate_cves_for_llm=len(eligible),
        llm_calls=llm_calls,
        llm_extracted=len(extracted_cpe_rows),
        matcher=matcher_stats,
        elapsed_seconds=elapsed,
    )
    logger.info(
        "Rescan done in %.1fs: candidates=%d llm_calls=%d extracted=%d "
        "findings_created=%d probable_exposures=%d",
        elapsed, stats.candidate_cves_for_llm, stats.llm_calls, stats.llm_extracted,
        matcher_stats.findings_created, matcher_stats.probable_exposures_created,
    )
    return stats


def trigger_rescan_background(reason: str, focus_vendor: str | None = None) -> asyncio.Task:
    """Fire-and-forget async task. Returns the Task so the caller can
    inspect/await it if desired (e.g. in tests), but does not block."""
    return asyncio.create_task(run_rescan_sync(reason, focus_vendor))
