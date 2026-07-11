"""Smoke test: verify Feodo Tracker Auth-Key + fetcher pipeline works.

No DB required — validates only the fetcher layer.

Usage:
    python scripts/smoke_feodo.py
"""
from __future__ import annotations

import asyncio
import logging
import sys
from collections import Counter

from ati_evn.config import get_settings
from ati_evn.fetchers.ioc.feodo import FeodoFetcher


async def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )

    settings = get_settings()
    if not settings.abuse_ch_auth_key:
        print("ERROR: ABUSE_CH_AUTH_KEY missing from .env — cannot smoke-test.")
        return 2

    fetcher = FeodoFetcher()
    print("\n=== Feodo Tracker smoke test — online C&C IPs ===")

    iocs = await fetcher.fetch()

    if not iocs:
        print("No online C&C IPs returned right now. Check Auth-Key validity or network.")
        return 1

    by_malware = Counter(i.metadata.get("malware") or "unknown" for i in iocs).most_common(10)

    print(f"Total IOCs   : {len(iocs)}")
    print(f"By malware   : {dict(by_malware)}")

    print("\n--- Sample (first 5) ---")
    for i, ioc in enumerate(iocs[:5], 1):
        port = ioc.metadata.get("port")
        malware = ioc.metadata.get("malware") or "?"
        country = ioc.metadata.get("country") or "?"
        print(f"[{i}] ipv4     {ioc.ioc_value:20s} port={port} sev={ioc.severity_hint:6s} "
              f"malware={malware} country={country}")

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
