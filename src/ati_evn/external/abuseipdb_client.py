"""AbuseIPDB API client — free tier 1000/day for /check endpoint.

Endpoint: GET https://api.abuseipdb.com/api/v2/check
Auth: Key: <key> header (NOT Authorization: Bearer -- verified live)
Params: ipAddress, maxAgeInDays

Response shape (verified live):
  {"data": {"ipAddress": "...", "abuseConfidenceScore": int,
            "countryCode": "US", "isp": "...", "usageType": "...",
            "isTor": bool, "totalReports": int, "lastReportedAt": "...",
            "hostnames": [...], "domain": "..."}}

Severity threshold: abuseConfidenceScore >= 75 -> is_malicious (industry
convention, not an AbuseIPDB-defined cutoff).
"""
from __future__ import annotations

import logging

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from ati_evn.config import get_settings

logger = logging.getLogger("ati_evn.external.abuseipdb")

CHECK_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBConfigError(Exception):
    pass


class AbuseIPDBQuotaExceeded(Exception):
    pass


class AbuseIPDBAPIError(Exception):
    pass


def _normalize(raw: dict) -> dict:
    data = raw.get("data") or {}
    abuse_confidence = int(data.get("abuseConfidenceScore") or 0)
    total_reports = int(data.get("totalReports") or 0)
    country = (data.get("countryCode") or "")[:80]
    isp = (data.get("isp") or "")[:200]
    usage_type = data.get("usageType") or ""
    is_tor = bool(data.get("isTor"))
    last_reported = data.get("lastReportedAt")
    hostnames = data.get("hostnames") or []
    domain = data.get("domain") or ""

    is_malicious = abuse_confidence >= 75

    return {
        "risk_score": float(abuse_confidence),
        "country": country,
        "isp": isp,
        "is_malicious": is_malicious,
        "data": {
            "abuse_confidence": abuse_confidence,
            "total_reports": total_reports,
            "usage_type": usage_type,
            "is_tor": is_tor,
            "last_reported": last_reported,
            "hostnames": hostnames,
            "domain": domain,
        },
    }


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(min=1, max=8),
    retry=retry_if_exception_type(httpx.RequestError),
    reraise=True,
)
async def check_ip(ip: str) -> dict:
    """Check one IP. Return normalized dict or raise."""
    settings = get_settings()
    if not settings.abuseipdb_api_key:
        raise AbuseIPDBConfigError("ABUSEIPDB_API_KEY missing in .env")

    headers = {"Key": settings.abuseipdb_api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": settings.abuseipdb_max_age_days}

    async with httpx.AsyncClient(timeout=8.0, headers=headers) as client:
        resp = await client.get(CHECK_URL, params=params)

    remaining = resp.headers.get("X-RateLimit-Remaining")
    if remaining is not None:
        try:
            if int(remaining) < 20:
                logger.warning("AbuseIPDB quota low: %s remaining today", remaining)
        except ValueError:
            pass

    if resp.status_code == 429:
        raise AbuseIPDBQuotaExceeded(f"Rate limited: {resp.text[:200]}")
    if resp.status_code == 401:
        raise AbuseIPDBConfigError(f"Auth failed (401). Check ABUSEIPDB_API_KEY. {resp.text[:200]}")
    if resp.status_code == 422:
        raise AbuseIPDBAPIError(f"Invalid IP: {ip}")
    if resp.status_code >= 400:
        raise AbuseIPDBAPIError(f"HTTP {resp.status_code}: {resp.text[:300]}")

    return _normalize(resp.json())
