"""Manual campaign detection trigger (for verification and debug).

Usage:
  python scripts/run_campaign_detection.py           # once
  python scripts/run_campaign_detection.py --dry     # detect only, no persist
"""
import argparse
import asyncio
import logging
import sys

from ati_evn.campaigns.detector import detect_campaigns, run_detection_once
from ati_evn.db.session import async_session


async def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry", action="store_true",
                     help="Detect only, don't persist to DB")
    args = ap.parse_args()

    if args.dry:
        async with async_session() as session:
            detected = await detect_campaigns(session)
        print(f"\n=== Detected {len(detected)} candidate campaigns (DRY) ===\n")
        for i, c in enumerate(detected, 1):
            print(f"[{i}] customer_id={c['customer_id']} "
                  f"confidence={c['confidence']} "
                  f"findings={len(c['findings'])} "
                  f"reason={c['detection_reason']}")
    else:
        stats = await run_detection_once()
        print("\n=== Campaign detection stats ===")
        for k, v in stats.items():
            print(f"  {k:10s}: {v}")


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
