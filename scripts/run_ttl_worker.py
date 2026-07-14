"""TTL worker — runs every 5 minutes.

Usage:
  python scripts/run_ttl_worker.py               # loop forever
  python scripts/run_ttl_worker.py --once        # single check + exit
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from ati_evn.alerts.ttl_worker import run_ttl_check_once


async def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args()

    if args.once:
        n = await run_ttl_check_once()
        print(f"Transitioned {n} findings to EXPIRED")
        return 0

    scheduler = AsyncIOScheduler()
    scheduler.add_job(run_ttl_check_once, "interval", minutes=5, id="ttl")
    scheduler.start()
    logging.getLogger("ttl").info("TTL worker running; check every 5 min")
    try:
        await asyncio.Event().wait()  # forever
    except KeyboardInterrupt:
        scheduler.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
