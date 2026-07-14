"""Clone/pull SigmaHQ and index rules into sigma_rules table.

Usage:
  python scripts/sync_sigma.py                  # first run: full clone
  python scripts/sync_sigma.py --update         # git pull + reindex changed
"""
from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path

from ati_evn.config import get_settings
from ati_evn.rules.sigma_sync import sync_sigma_rules


async def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )
    ap = argparse.ArgumentParser()
    ap.add_argument("--update", action="store_true",
                     help="Same as default — clone_or_pull always pulls if repo exists.")
    ap.parse_args()

    settings = get_settings()
    repo_dir = Path(settings.sigma_repo_dir).expanduser().resolve()

    stats = await sync_sigma_rules(repo_dir)
    print("\n=== Sigma sync complete ===")
    for k, v in stats.items():
        print(f"  {k:12s}: {v}")


if __name__ == "__main__":
    asyncio.run(main())
