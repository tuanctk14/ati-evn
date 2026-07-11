"""Lazy LLM CPE inference for CVE detections NVD hasn't attached CPE data to.

Only calls the LLM when a candidate CVE's description mentions at least one
EVN asset vendor/product keyword — this is the cost-control pre-filter.
Confident inferences (confidence >= --min-conf) are upserted into
cve_product_map with source='llm_inferred'.

Usage:
    python scripts/run_cpe_inference.py                # infer for unmatched CVE dets
    python scripts/run_cpe_inference.py --limit 50     # cap number of LLM calls
    python scripts/run_cpe_inference.py --min-conf 0.7 # only insert if confidence >= X
    python scripts/run_cpe_inference.py --dry-run      # log inferences, don't INSERT
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert

from ati_evn.config import get_settings
from ati_evn.db.models import CveProductMap, Detection, DetectionStatus
from ati_evn.db.session import async_session
from ati_evn.llm.candidate_filter import load_hint_keywords, text_matches_any_keyword
from ati_evn.llm.client import LLMClient, LLMError
from ati_evn.llm.cpe_inferrer import infer_cpe_for_cve

logger = logging.getLogger("ati_evn.run_cpe_inference")

CANDIDATE_QUERY = text("""
    SELECT d.id, d.ioc_value, d.raw_text
    FROM detections d
    WHERE d.ioc_type = 'cve_id'
      AND d.status = 'UNMATCHED'
      AND d.raw_text IS NOT NULL
      AND length(d.raw_text) > 20
      AND NOT EXISTS (
        SELECT 1 FROM cve_product_map cpm
        WHERE cpm.cve_id = d.ioc_value
      )
""")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=None, help="Cap number of LLM calls made.")
    parser.add_argument("--min-conf", type=float, default=0.6,
                         help="Only insert inferences with confidence >= this (default 0.6).")
    parser.add_argument("--dry-run", action="store_true",
                         help="Log inferences; make no DB writes.")
    return parser.parse_args()


async def _upsert_inferred(session, cve_id: str, inferred) -> None:
    stmt = pg_insert(CveProductMap).values(
        cve_id=cve_id,
        vendor=inferred.vendor,
        product=inferred.product,
        version_range=inferred.version_range or None,
        source="llm_inferred",
        confidence=inferred.confidence,
        reasoning=inferred.reasoning,
    )
    stmt = stmt.on_conflict_do_nothing(constraint="uq_cpm_row")
    await session.execute(stmt)


async def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )
    args = parse_args()

    settings = get_settings()
    if not settings.openai_api_key:
        print("ERROR: OPENAI_API_KEY missing from .env — cannot run LLM CPE inference.")
        return 2

    client = LLMClient(settings)

    attempted = 0
    llm_successes = 0
    llm_errors = 0
    extracted = 0
    inserted = 0
    skipped_low_confidence = 0
    skipped_no_match = 0

    sample_results: list[tuple[str, object]] = []

    async with async_session() as session:
        hint_keywords = await load_hint_keywords(session)
        logger.info("Loaded %d hint keywords from customer_assets", len(hint_keywords))

        rows = (await session.execute(CANDIDATE_QUERY)).all()
        logger.info("Candidate CVEs missing CPE data: %d", len(rows))

        pre_filtered: list[tuple[int, str, str, str]] = []
        for det_id, cve_id, raw_text in rows:
            matched_keyword = text_matches_any_keyword(raw_text, hint_keywords)
            if matched_keyword is None:
                skipped_no_match += 1
                continue
            pre_filtered.append((det_id, cve_id, raw_text, matched_keyword))

        logger.info("Candidates passing keyword pre-filter: %d", len(pre_filtered))

        if args.limit is not None:
            pre_filtered = pre_filtered[: args.limit]

        for det_id, cve_id, raw_text, matched_keyword in pre_filtered:
            attempted += 1
            try:
                results = await infer_cpe_for_cve(
                    client, cve_id, raw_text, context_hint_vendors=hint_keywords,
                )
                llm_successes += 1
            except LLMError as e:
                llm_errors += 1
                logger.error("CVE %s: LLM call failed: %s", cve_id, e)
                continue

            extracted += len(results)

            for inferred in results:
                sample_results.append((cve_id, inferred))
                if inferred.confidence < args.min_conf:
                    skipped_low_confidence += 1
                    continue
                if not args.dry_run:
                    await _upsert_inferred(session, cve_id, inferred)
                inserted += 1

        if not args.dry_run:
            await session.commit()

    print("\nLLM CPE Inference Complete")
    print("============================")
    print(f"Candidate CVEs (missing CPE + hint match): {len(pre_filtered)}")
    print(f"LLM calls made:                            {attempted}")
    print(f"LLM successes:                             {llm_successes}")
    print(f"LLM errors:                                {llm_errors}")
    print(f"CPE entries extracted:                     {extracted}")
    print(f"CPE entries inserted (confidence >= {args.min_conf}):  {inserted}")
    print(f"CPE entries skipped (low confidence):      {skipped_low_confidence}")

    if sample_results:
        print("\n--- Sample inferences (first 10) ---")
        for cve_id, inferred in sample_results[:10]:
            print(f"  {cve_id}: vendor={inferred.vendor} product={inferred.product} "
                  f"version_range={inferred.version_range!r} confidence={inferred.confidence:.2f}")
            print(f"      reasoning: {inferred.reasoning}")

    if args.dry_run:
        print("\n(dry-run: no writes were made)")
    else:
        print("\nNow re-run matcher to pick up new mappings:")
        print("    python scripts/run_matcher.py --all")

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
