"""Smoke test: verify NVD API key + fetcher pipeline works.

No DB required — validates only the fetcher layer. Also prints a sample
cve_product_map row extracted from CPE data (the ingest pipeline handles
the actual insert; this script just proves extraction works).

Usage:
    python scripts/smoke_nvd.py
"""
from __future__ import annotations

import asyncio
import logging
import sys
from collections import Counter

from ati_evn.config import get_settings
from ati_evn.fetchers.cve.nvd import NVDFetcher


async def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )

    settings = get_settings()
    if not settings.nvd_api_key:
        print("ERROR: NVD_API_KEY missing from .env — cannot smoke-test.")
        return 2

    fetcher = NVDFetcher()
    print("\n=== NVD smoke test — last 48 hours (lastModified window) ===")

    iocs, product_rows = await fetcher.fetch(since_hours=48)

    if not iocs:
        print("No CVEs returned. Check API key validity or network.")
        return 1

    by_sev = Counter(i.severity_hint for i in iocs)

    print(f"Total CVEs        : {len(iocs)}")
    print(f"By severity       : {dict(by_sev)}")
    print(f"cve_product_map   : {len(product_rows)} rows")

    print("\n--- CVE sample (first 5) ---")
    for i, ioc in enumerate(iocs[:5], 1):
        score = ioc.metadata.get("cvss_score")
        desc = (ioc.raw_text or "")[:80]
        print(f"[{i}] {ioc.ioc_value:18s} sev={ioc.severity_hint:8s} cvss={score} {desc}...")

    if product_rows:
        print("\n--- cve_product_map sample (first 5) ---")
        for i, row in enumerate(product_rows[:5], 1):
            print(f"[{i}] {row['cve_id']:18s} vendor={row['vendor']:20s} "
                  f"product={row['product']:25s} range={row['version_range']}")
    else:
        print("\nNo cve_product_map rows extracted in this window (no CPE data on these CVEs).")

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
