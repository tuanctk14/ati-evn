"""Smoke test: verify ThreatFox Auth-Key + fetcher pipeline works.

Runs the fetcher, prints a summary + a few sample IOCs.
No DB required — validates only the fetcher layer.

Usage:
    cd ati-evn
    cp .env.example .env
    pip install -e .
    python scripts/smoke_threatfox.py
"""
from __future__ import annotations

import asyncio
import logging
import sys
from collections import Counter

from ati_evn.config import get_settings
from ati_evn.fetchers.ioc.threatfox import ThreatFoxFetcher


async def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )

    settings = get_settings()

    if not settings.abuse_ch_auth_key:
        print("ERROR: ABUSE_CH_AUTH_KEY missing from .env — cannot smoke-test.")
        return 2

    fetcher = ThreatFoxFetcher()
    print(f"\n=== ThreatFox smoke test — last 24 hours ===")
    print(f"Auth-Key (last 8): ...{settings.abuse_ch_auth_key[-8:]}\n")

    iocs = await fetcher.fetch(since_hours=24)

    if not iocs:
        print("No IOCs returned. Check Auth-Key validity or network.")
        return 1

    # Summary
    by_type = Counter(i.ioc_type for i in iocs)
    by_sev = Counter(i.severity_hint for i in iocs)
    by_malware = Counter(
        (i.metadata.get("malware_printable") or "unknown") for i in iocs
    ).most_common(10)

    print(f"Total IOCs   : {len(iocs)}")
    print(f"By type      : {dict(by_type)}")
    print(f"By severity  : {dict(by_sev)}")
    print(f"Top malware  :")
    for name, cnt in by_malware:
        print(f"  {cnt:5d}  {name}")

    print(f"\n--- Sample (first 5) ---")
    for i, ioc in enumerate(iocs[:5], 1):
        conf = ioc.metadata.get("confidence_level")
        mal = ioc.metadata.get("malware_printable") or "?"
        print(f"[{i}] {ioc.ioc_type:8s} {ioc.ioc_value:50s} sev={ioc.severity_hint:6s} conf={conf} malware={mal}")

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
