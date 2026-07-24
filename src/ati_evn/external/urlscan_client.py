"""urlscan.io API client — brand abuse monitoring (slice 11).

Two endpoints, verified live against the real key:

  GET https://urlscan.io/api/v1/search/   (Elasticsearch query syntax)
  Auth: API-Key: <key>
  Params: q, size (max 10000 but rate-limited practically)

  Search result rows do NOT carry `verdicts` -- confirmed live, every
  row's `results[].verdicts` is `{}`. Only `page`, `task`, `stats`,
  `screenshot` are populated. `task.uuid` is the scan id used to fetch
  the real verdict via the per-scan Result API:

  GET https://urlscan.io/api/v1/result/{uuid}/
  Auth: API-Key: <key>

  Result API's `verdicts` shape (verified live):
    {
      "overall": {"score": int, "malicious": bool, "categories": [...],
                   "brands": [...], "hasVerdicts": bool},
      "engines": {"score": int, "malicious": bool, "enginesTotal": int,
                   "maliciousTotal": int, "benignTotal": int, ...},
      "community": {"score": int, "malicious": bool,
                     "votesTotal": int, "votesMalicious": int, ...}
    }
  Note: engines.malicious can be true with maliciousTotal == 0 -- it
  reflects urlscan's own ML score (engines.score), not a vendor vote
  count. Rules that key on "engine count" must read maliciousTotal
  explicitly, not just engines.malicious.

  Rate limit (verified via response headers): 120 search calls/min,
  10 concurrent. Result API calls are comparatively cheap; we still
  fetch them sequentially per candidate to stay well under any quota.

  No Hostname History API use (Pro-tier only, confirmed 403 on the
  free key in a prior session) and no new-scan submission -- this
  client only reads scans that already exist in urlscan's public index.
"""
from __future__ import annotations

import logging

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from ati_evn.config import get_settings

logger = logging.getLogger("ati_evn.external.urlscan")

BASE_URL = "https://urlscan.io/api/v1"


class UrlscanConfigError(Exception):
    pass


class UrlscanAPIError(Exception):
    pass


def _normalize_search_row(raw: dict, keyword: str) -> dict:
    page = raw.get("page") or {}
    task = raw.get("task") or {}
    return {
        "scan_uuid": task.get("uuid") or "",
        "url": page.get("url") or task.get("url") or "",
        "domain": page.get("domain") or task.get("domain") or "",
        "page_title": (page.get("title") or "")[:500] or None,
        "keyword_matched": keyword,
        "raw": raw,
    }


def _normalize_verdicts(result_raw: dict) -> dict:
    verdicts = result_raw.get("verdicts") or {}
    overall = verdicts.get("overall") or {}
    engines = verdicts.get("engines") or {}
    community = verdicts.get("community") or {}
    return {
        "verdict_malicious": bool(overall.get("malicious")),
        "verdict_score": overall.get("score"),
        "engines_malicious_total": engines.get("maliciousTotal"),
        "community_votes_malicious": community.get("votesMalicious"),
        "brands": overall.get("brands") or [],
        "categories": overall.get("categories") or [],
    }


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(min=1, max=10),
    retry=retry_if_exception_type(httpx.RequestError),
    reraise=True,
)
async def _search(query: str, size: int) -> dict:
    settings = get_settings()
    if not settings.urlscan_api_key:
        raise UrlscanConfigError("URLSCAN_API_KEY missing in .env")

    headers = {"API-Key": settings.urlscan_api_key, "Accept": "application/json"}
    params = {"q": query, "size": size}

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(f"{BASE_URL}/search/", params=params, headers=headers)

    if resp.status_code == 401:
        raise UrlscanConfigError(f"Auth failed (401). Check API key. {resp.text[:200]}")
    if resp.status_code == 429:
        raise UrlscanAPIError(f"Rate limited (429): {resp.text[:200]}")
    if resp.status_code >= 400:
        raise UrlscanAPIError(f"HTTP {resp.status_code}: {resp.text[:300]}")
    return resp.json()


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(min=1, max=10),
    retry=retry_if_exception_type(httpx.RequestError),
    reraise=True,
)
async def _get_result(scan_uuid: str) -> dict:
    settings = get_settings()
    headers = {"API-Key": settings.urlscan_api_key, "Accept": "application/json"}

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(f"{BASE_URL}/result/{scan_uuid}/", headers=headers)

    if resp.status_code == 404:
        # Scan expired or was private -- skip, not a hard error.
        return {}
    if resp.status_code == 429:
        raise UrlscanAPIError(f"Rate limited (429) fetching result {scan_uuid}")
    if resp.status_code >= 400:
        raise UrlscanAPIError(f"HTTP {resp.status_code} fetching result {scan_uuid}: {resp.text[:300]}")
    return resp.json()


async def search_brand(keyword: str, domain: str | None, max_results: int = 50) -> list[dict]:
    """Search urlscan for a brand/keyword, then fetch verdicts per hit.

    Query strategy A+C: domain:X OR page.title:"Brand" for the keyword,
    each row enriched with a per-scan Result API call for verdicts.
    """
    query_parts = [f'page.title:"{keyword}"']
    if domain:
        query_parts.append(f"domain:{domain}")
    query = " OR ".join(query_parts)

    raw = await _search(query, max_results)
    rows = raw.get("results") or []

    sightings: list[dict] = []
    for row in rows[:max_results]:
        normalized = _normalize_search_row(row, keyword)
        if not normalized["scan_uuid"]:
            continue
        result_raw = await _get_result(normalized["scan_uuid"])
        normalized.update(_normalize_verdicts(result_raw))
        normalized["result_raw"] = result_raw
        sightings.append(normalized)

    logger.info("urlscan search '%s': %d sightings", keyword, len(sightings))
    return sightings
