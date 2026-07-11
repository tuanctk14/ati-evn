"""Manual rescan — no asset add. Re-checks unmatched CVE detections against
the current asset inventory, running LLM CPE/CWE inference where the filter
now says a vendor is in scope.

Usage:
    python scripts/rescan.py                           # full rescan
    python scripts/rescan.py --focus-vendor microsoft   # scope narrowed
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from ati_evn.rescan import run_rescan_sync


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--focus-vendor", type=str, default=None,
                         help="Narrow the LLM eligibility filter to just this vendor.")
    return parser.parse_args()


async def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )
    args = parse_args()

    stats = await run_rescan_sync("manual", focus_vendor=args.focus_vendor)

    print("\n=== RescanStats ===")
    print(f"candidate_cves_for_llm : {stats.candidate_cves_for_llm}")
    print(f"llm_calls              : {stats.llm_calls}")
    print(f"llm_extracted          : {stats.llm_extracted}")
    print(f"elapsed_seconds        : {stats.elapsed_seconds:.1f}")
    print("\n--- matcher (RouteStats) ---")
    print(f"detections_processed        : {stats.matcher.detections_processed}")
    print(f"detections_matched          : {stats.matcher.detections_matched}")
    print(f"detections_unmatched        : {stats.matcher.detections_unmatched}")
    print(f"findings_created            : {stats.matcher.findings_created}")
    print(f"findings_merged             : {stats.matcher.findings_merged}")
    print(f"findings_auto_fp            : {stats.matcher.findings_auto_fp}")
    print(f"probable_exposures_created  : {stats.matcher.probable_exposures_created}")
    print(f"per_strategy                : {stats.matcher.per_strategy}")

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
