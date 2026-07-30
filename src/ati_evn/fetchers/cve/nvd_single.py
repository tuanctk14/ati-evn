"""On-demand fetch of a single CVE by ID. Used by /rule (and /playbook)
fallback when a CVE isn't in cve_product_map/cve_cwe_map/detections yet
(NVD's batch fetcher only pulls a rolling lastModified window, so an old
or just-published CVE outside that window won't be present).

Reuses NVDFetcher._process_one — the exact same CPE/CWE extraction + inline
LLM gap-fill logic the batch fetcher uses — via the `cveId=` query param
instead of a lastModified window, so there is no parsing logic duplicated
here.
"""
from __future__ import annotations

import asyncio
import logging

import httpx

from ati_evn.db.session import async_session
from ati_evn.db.queries import load_evn_vendors_lowercase
from ati_evn.fetchers.cve.nvd import NVD_URL, NVDFetcher
from ati_evn.ingest.pipeline import ingest_cve_batch
from ati_evn.llm.client import LLMClient

logger = logging.getLogger("ati_evn.fetchers.nvd_single")


async def fetch_single_cve(cve_id: str) -> bool:
    """Return True if the CVE was fetched from NVD and ingested; False if
    NVD has no record of it or the request failed."""
    fetcher = NVDFetcher()
    if not fetcher.is_configured():
        logger.warning("NVD_API_KEY missing — cannot fetch %s on demand", cve_id)
        return False

    cve_id = cve_id.upper().strip()
    headers = {"apiKey": fetcher.settings.nvd_api_key}

    try:
        async with await fetcher._http_client(extra_headers=headers) as client:
            resp = await fetcher._get(client, NVD_URL, params={"cveId": cve_id})
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPStatusError as e:
        logger.warning("NVD single fetch %s: HTTP %s", cve_id, e.response.status_code)
        return False
    except (httpx.HTTPError, ValueError) as e:
        logger.warning("NVD single fetch %s failed: %s", cve_id, e)
        return False

    vulns = data.get("vulnerabilities") or []
    if not vulns:
        logger.info("NVD has no record of %s", cve_id)
        return False

    cve_raw = vulns[0].get("cve") or {}

    evn_vendors = await load_evn_vendors_lowercase()
    llm_client = LLMClient(fetcher.settings) if fetcher.settings.openai_api_key else None
    sem = asyncio.Semaphore(fetcher.settings.llm_max_concurrent)

    result = await fetcher._process_one(cve_raw, evn_vendors, llm_client, sem)
    if result["raw_ioc"] is None:
        logger.warning("NVD single fetch %s: malformed CVE payload", cve_id)
        return False

    payload = {
        "raw_iocs": [result["raw_ioc"]],
        "cpe_rows": result["cpe_rows"],
        "cwe_rows": result["cwe_rows"],
    }

    async with async_session() as session:
        await ingest_cve_batch(session, payload)

    logger.info(
        "NVD single fetch %s: ingested (%d CPE rows, %d CWE rows)",
        cve_id, len(result["cpe_rows"]), len(result["cwe_rows"]),
    )
    return True
