"""Seed EVN + 11 subsidiaries + mixed IT/ICS asset inventory.

Idempotent — safe to rerun.

Usage:
    python scripts/seed_evn.py
"""
from __future__ import annotations

import asyncio
import logging
import sys

from ati_evn.db.session import async_session
from ati_evn.seed.evn import seed_evn


async def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )
    async with async_session() as session:
        await seed_evn(session)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
