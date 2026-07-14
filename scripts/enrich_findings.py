"""Backfill attack_context on Findings that don't yet have it.

Usage:
    python scripts/enrich_findings.py                  # process all missing
    python scripts/enrich_findings.py --force          # re-enrich even if present
    python scripts/enrich_findings.py --limit 20       # cap number processed
    python scripts/enrich_findings.py --only-cve       # skip IOC findings
    python scripts/enrich_findings.py --no-bert        # chain-only (fast, offline)

Prints a per-finding progress line every 20 findings, then a summary at the
end. Safe to interrupt (Ctrl-C) — the last committed batch stays.

Requires:
  - Slice 4 REDO has been applied (CveCweMap table exists)
  - Optional: `python scripts/setup_embeddings.py` for BERT semantic similarity
    (skip via --no-bert if you only want deterministic chain enrichment)
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import time
from collections import Counter

from sqlalchemy import select

from ati_evn.db.models import Finding
from ati_evn.db.session import async_session


async def main_async(args) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )

    # Import here so --no-bert can skip the torch import path
    from ati_evn.enrichment.orchestrator import enrich_finding, load_smet_lazy

    mapper = None
    if not args.no_bert:
        mapper = load_smet_lazy()
        if mapper is None:
            print("[WARN] BERT mapper not available. Continuing with chain-only.")
        else:
            print(f"[OK] BERT mapper loaded ({len(mapper.technique_ids)} techniques cached).")

    counters = Counter()
    start = time.monotonic()

    async with async_session() as session:
        # Query candidates
        stmt = select(Finding).order_by(Finding.id)
        if args.only_cve:
            stmt = stmt.where(Finding.ioc_type == "cve_id")
        result = await session.execute(stmt)
        all_findings = list(result.scalars())

        if not args.force:
            all_findings = [
                f for f in all_findings
                if not (f.metadata_ and "attack_context" in f.metadata_)
            ]

        if args.limit:
            all_findings = all_findings[: args.limit]

        total = len(all_findings)
        print(f"\n[INFO] {total} findings queued for enrichment.\n")

        for i, finding in enumerate(all_findings, 1):
            try:
                ctx = await enrich_finding(session, finding, smet_mapper=mapper)
                if ctx:
                    counters["enriched"] += 1
                    counters["techniques"] += len(ctx.get("techniques") or [])
                    if ctx.get("smet_used"):
                        counters["smet_used"] += 1
                    if ctx.get("chain_used"):
                        counters["chain_used"] += 1
                    if ctx.get("ioc_heuristic_used"):
                        counters["ioc_heuristic_used"] += 1
                else:
                    counters["empty_context"] += 1
            except Exception as e:
                counters["errors"] += 1
                logging.warning("Enrichment failed for Finding %d: %s", finding.id, e)

            if i % 20 == 0 or i == total:
                await session.commit()
                elapsed = time.monotonic() - start
                rate = i / elapsed if elapsed > 0 else 0
                print(f"  [{i}/{total}] enriched, {rate:.1f}/s, "
                      f"elapsed {elapsed:.1f}s")

    elapsed = time.monotonic() - start
    print("\n" + "=" * 60)
    print("  Enrichment Complete")
    print("=" * 60)
    print(f"  Total processed     : {total}")
    print(f"  Successfully enriched: {counters['enriched']}")
    print(f"  Empty context        : {counters['empty_context']}")
    print(f"  Errors               : {counters['errors']}")
    print(f"  SMET used            : {counters['smet_used']}")
    print(f"  Chain used           : {counters['chain_used']}")
    print(f"  IOC heuristic used   : {counters['ioc_heuristic_used']}")
    print(f"  Total techniques     : {counters['techniques']}")
    print(f"  Elapsed              : {elapsed:.1f}s")
    print("=" * 60)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true",
                    help="Re-enrich findings that already have attack_context")
    ap.add_argument("--limit", type=int, default=0,
                    help="Cap the number of findings processed (0 = no cap)")
    ap.add_argument("--only-cve", action="store_true",
                    help="Skip non-CVE findings")
    ap.add_argument("--no-bert", action="store_true",
                    help="Skip BERT semantic similarity; use CWE chain only")
    args = ap.parse_args()
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    sys.exit(main())
