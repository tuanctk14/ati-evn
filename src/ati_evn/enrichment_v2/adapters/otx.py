"""AlienVault OTX per-IP adapter.

Endpoint: /api/v1/indicators/IPv4/{ip}/general

Verdict from pulse count:
  >= malicious_pulses -> malicious
  >= suspicious_pulses -> suspicious
  0 -> benign

Note: earlier probe showed intermittent timeouts on some IPs. Use a
generous timeout + graceful fallback (unknown, not error) on timeout.
"""
from __future__ import annotations

import logging

import httpx

from ati_evn.config import get_settings
from ati_evn.enrichment_v2.adapters._base import BaseIpAdapter, ProviderVerdict, Verdict
from ati_evn.enrichment_v2.config import get_provider_config

logger = logging.getLogger("ati_evn.enrichment_v2.adapters.otx")

URL_TEMPLATE = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"


class OTXAdapter(BaseIpAdapter):
    provider_name = "otx"

    async def fetch(self, ip: str) -> ProviderVerdict:
        settings = get_settings()
        if not settings.otx_api_key:
            return self._mk_error("OTX_API_KEY missing")

        headers = {"X-OTX-API-KEY": settings.otx_api_key}
        url = URL_TEMPLATE.format(ip=ip)

        try:
            async with httpx.AsyncClient(timeout=15.0, headers=headers) as client:
                resp = await client.get(url)
            if resp.status_code == 401:
                return self._mk_error("Auth failed (401)")
            if resp.status_code >= 400:
                return self._mk_error(f"HTTP {resp.status_code}")
            data = resp.json()
        except httpx.TimeoutException:
            logger.info("OTX timeout for %s (known intermittent issue)", ip)
            return ProviderVerdict(
                provider=self.provider_name,
                normalized_score=0.0,
                verdict="unknown",
                confidence=0.0,
                error="OTX API timeout",
            )
        except Exception as e:
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

        verdict, confidence = self._map_verdict(pulse_count)

        if pulse_count == 0:
            norm_score = 0.0
        elif pulse_count == 1:
            norm_score = 25.0
        elif pulse_count == 2:
            norm_score = 50.0
        elif pulse_count < 5:
            norm_score = 65.0
        else:
            norm_score = min(90.0, 65.0 + pulse_count * 2)

        return ProviderVerdict(
            provider=self.provider_name,
            normalized_score=norm_score,
            verdict=verdict,
            confidence=confidence,
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

    def _map_verdict(self, pulse_count: int) -> tuple[Verdict, float]:
        cfg = get_provider_config("otx")
        mal_threshold = cfg.get("malicious_pulses", 3)
        susp_threshold = cfg.get("suspicious_pulses", 1)

        if pulse_count >= mal_threshold:
            verdict: Verdict = "malicious"
            confidence = min(1.0, 0.6 + pulse_count * 0.05)
        elif pulse_count >= susp_threshold:
            verdict = "suspicious"
            confidence = 0.5
        else:
            verdict = "benign"
            confidence = 0.6
        return verdict, confidence
