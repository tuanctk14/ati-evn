"""Smoke test: verify URLhaus Auth-Key + fetcher pipeline works.

No DB required — validates only the fetcher layer.

Usage:
    python scripts/smoke_urlhaus.py
"""
from __future__ import annotations

import asyncio
import logging
import sys
from collections import Counter

from ati_evn.config import get_settings
from ati_evn.fetchers.ioc.urlhaus import URLhausFetcher


async def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )

    settings = get_settings()
    if not settings.abuse_ch_auth_key:
        print("ERROR: ABUSE_CH_AUTH_KEY missing from .env — cannot smoke-test.")
        return 2

    fetcher = URLhausFetcher()
    print("\n=== URLhaus smoke test — recent malicious URLs ===")

    iocs = await fetcher.fetch()

    if not iocs:
        print("No URLs returned. Check Auth-Key validity or network.")
        return 1

    by_sev = Counter(i.severity_hint for i in iocs)
    by_threat = Counter(i.metadata.get("threat") or "unknown" for i in iocs).most_common(10)

    print(f"Total IOCs   : {len(iocs)}")
    print(f"By severity  : {dict(by_sev)}")
    print(f"By threat    : {dict(by_threat)}")

    print("\n--- Sample (first 5) ---")
    for i, ioc in enumerate(iocs[:5], 1):
        host = ioc.metadata.get("host") or "?"
        threat = ioc.metadata.get("threat") or "?"
        print(f"[{i}] url sev={ioc.severity_hint:6s} host={host:30s} threat={threat}")
        print(f"      {ioc.ioc_value}")

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
