"""AbuseIPDB adapter -- ProviderSignal only, no scoring.

Scoring/verdict determination lives in enrichment_v2/scoring.py
(ScoringEngine), driven by enrichment_config.yaml.
"""
from __future__ import annotations

import logging

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from ati_evn.config import get_settings
from ati_evn.enrichment_v2.adapters._base import BaseIpAdapter, ProviderSignal

logger = logging.getLogger("ati_evn.enrichment_v2.adapters.abuseipdb")

URL = "https://api.abuseipdb.com/api/v2/check"


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(min=1, max=8),
    retry=retry_if_exception_type(httpx.RequestError),
    reraise=True,
)
async def _get(headers: dict, params: dict) -> httpx.Response:
    async with httpx.AsyncClient(timeout=10.0, headers=headers) as client:
        return await client.get(URL, params=params)


class AbuseIPDBAdapter(BaseIpAdapter):
    provider_name = "abuseipdb"

    async def fetch(self, ip: str) -> ProviderSignal:
        settings = get_settings()
        if not settings.abuseipdb_api_key:
            return self._mk_error("ABUSEIPDB_API_KEY missing")

        headers = {"Key": settings.abuseipdb_api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        try:
            resp = await _get(headers, params)
            if resp.status_code == 429:
                return self._mk_error("Rate limited (quota exceeded)")
            if resp.status_code == 401:
                return self._mk_error("Auth failed (401)")
            if resp.status_code >= 400:
                return self._mk_error(f"HTTP {resp.status_code}")
            data = resp.json().get("data") or {}
        except Exception as e:
            logger.warning("AbuseIPDB fetch failed for %s: %s", ip, e)
            return self._mk_error(f"{type(e).__name__}: {str(e)[:100]}")

        return ProviderSignal(
            provider=self.provider_name,
            signals={
                "abuse_confidence": int(data.get("abuseConfidenceScore") or 0),
                "total_reports": int(data.get("totalReports") or 0),
                "usage_type": data.get("usageType"),
                "is_tor": bool(data.get("isTor")),
                "last_reported": data.get("lastReportedAt"),
                "hostnames": data.get("hostnames") or [],
                "domain": data.get("domain"),
            },
            country=(data.get("countryCode") or "")[:80] or None,
            isp=(data.get("isp") or "")[:200] or None,
            raw_data=data,
        )
