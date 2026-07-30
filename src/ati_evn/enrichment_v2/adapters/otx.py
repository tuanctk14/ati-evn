"""AlienVault OTX per-IP adapter. ProviderSignal only, no scoring.

Endpoint: /api/v1/indicators/IPv4/{ip}/general

Scoring/verdict determination lives in enrichment_v2/scoring.py
(ScoringEngine), driven by enrichment_config.yaml.

Note: earlier probe showed intermittent timeouts on some IPs. Use a
generous timeout + graceful fallback (unknown, not error) on timeout.
"""
from __future__ import annotations

import logging

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from ati_evn.config import get_settings
from ati_evn.enrichment_v2.adapters._base import BaseIpAdapter, ProviderSignal

logger = logging.getLogger("ati_evn.enrichment_v2.adapters.otx")

URL_TEMPLATE = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(min=1, max=8),
    retry=retry_if_exception_type(httpx.RequestError),
    reraise=True,
)
async def _get(url: str, headers: dict) -> httpx.Response:
    async with httpx.AsyncClient(timeout=15.0, headers=headers) as client:
        return await client.get(url)


class OTXAdapter(BaseIpAdapter):
    provider_name = "otx"

    async def fetch(self, ip: str) -> ProviderSignal:
        settings = get_settings()
        if not settings.otx_api_key:
            return self._mk_error("OTX_API_KEY missing")

        headers = {"X-OTX-API-KEY": settings.otx_api_key}
        url = URL_TEMPLATE.format(ip=ip)

        try:
            resp = await _get(url, headers)
            if resp.status_code == 401:
                return self._mk_error("Auth failed (401)")
            if resp.status_code >= 400:
                return self._mk_error(f"HTTP {resp.status_code}")
            data = resp.json()
        except httpx.TimeoutException:
            logger.info("OTX timeout for %s (known intermittent issue)", ip)
            return ProviderSignal(
                provider=self.provider_name,
                signals={},
                error="OTX API timeout",
            )
        except Exception as e:
            logger.warning("OTX fetch failed for %s: %s", ip, e)
            return self._mk_error(f"{type(e).__name__}: {str(e)[:100]}")

        pulse_info = data.get("pulse_info") or {}
        pulse_count = int(pulse_info.get("count") or 0)
        pulses = pulse_info.get("pulses") or []
        reputation = data.get("reputation", 0)

        pulse_summary = []
        for p in pulses[:10]:
            pulse_summary.append({
                "id": p.get("id"),
                "name": p.get("name"),
                "author": (p.get("author") or {}).get("username"),
                "malware_families": [
                    m.get("display_name") for m in (p.get("malware_families") or [])
                    if m.get("display_name")
                ][:5],
                "adversary": p.get("adversary"),
                "tags": p.get("tags") or [],
                "created": p.get("created"),
            })

        return ProviderSignal(
            provider=self.provider_name,
            signals={
                "pulse_count": pulse_count,
                "pulses": pulse_summary,
                "reputation": reputation,
                "asn": data.get("asn"),
            },
            country=data.get("country_code") or None,
            isp=data.get("asn") or None,
            raw_data={
                "pulse_count": pulse_count,
                "pulses": pulse_summary,
                "reputation": reputation,
                "asn": data.get("asn"),
                "country_code": data.get("country_code"),
                "city": data.get("city"),
            },
        )
