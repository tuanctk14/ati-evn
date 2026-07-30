"""VirusTotal adapter -- IP address lookup. ProviderSignal only, no scoring.

Scoring/verdict determination lives in enrichment_v2/scoring.py
(ScoringEngine), driven by enrichment_config.yaml.
"""
from __future__ import annotations

import logging

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from ati_evn.config import get_settings
from ati_evn.enrichment_v2.adapters._base import BaseIpAdapter, ProviderSignal

logger = logging.getLogger("ati_evn.enrichment_v2.adapters.virustotal")

BASE = "https://www.virustotal.com/api/v3"


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(min=1, max=8),
    retry=retry_if_exception_type(httpx.RequestError),
    reraise=True,
)
async def _get(url: str, headers: dict) -> httpx.Response:
    async with httpx.AsyncClient(timeout=12.0, headers=headers) as client:
        return await client.get(url)


class VirusTotalAdapter(BaseIpAdapter):
    provider_name = "virustotal"

    async def fetch(self, ip: str) -> ProviderSignal:
        settings = get_settings()
        if not settings.virustotal_api_key:
            return self._mk_error("VIRUSTOTAL_API_KEY missing")

        headers = {"x-apikey": settings.virustotal_api_key}
        url = f"{BASE}/ip_addresses/{ip}"

        try:
            resp = await _get(url, headers)
            if resp.status_code == 429:
                return self._mk_error("Rate limited (VT quota: 4/min, 500/day)")
            if resp.status_code == 401:
                return self._mk_error("Auth failed (401)")
            if resp.status_code == 404:
                return ProviderSignal(
                    provider=self.provider_name,
                    signals={
                        "not_found": True, "malicious_engines": 0,
                        "suspicious_engines": 0, "total_engines": 0,
                    },
                    raw_data={"not_found": True},
                )
            if resp.status_code >= 400:
                return self._mk_error(f"HTTP {resp.status_code}")
            attrs = resp.json().get("data", {}).get("attributes", {})
        except Exception as e:
            logger.warning("VirusTotal fetch failed for %s: %s", ip, e)
            return self._mk_error(f"{type(e).__name__}: {str(e)[:100]}")

        stats = attrs.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        harmless = int(stats.get("harmless") or 0)
        undetected = int(stats.get("undetected") or 0)
        total = malicious + suspicious + harmless + undetected

        return ProviderSignal(
            provider=self.provider_name,
            signals={
                "malicious_engines": malicious,
                "suspicious_engines": suspicious,
                "harmless_engines": harmless,
                "undetected_engines": undetected,
                "total_engines": total,
                "reputation": attrs.get("reputation"),
                "asn": attrs.get("asn"),
                "network": attrs.get("network"),
                "tags": attrs.get("tags") or [],
                "categories": attrs.get("categories") or {},
            },
            country=(attrs.get("country") or "")[:80] or None,
            isp=(attrs.get("as_owner") or "")[:200] or None,
            raw_data=attrs,
        )
