"""Pulsedive info.php per-IP adapter. ProviderSignal only, no scoring.

Endpoint: /api/info.php?indicator={ip}&key={key}
Returns: risk level (none/low/medium/high/critical) + threats + feeds

Scoring/verdict determination lives in enrichment_v2/scoring.py
(ScoringEngine), driven by enrichment_config.yaml.
"""
from __future__ import annotations

import logging

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from ati_evn.config import get_settings
from ati_evn.enrichment_v2.adapters._base import BaseIpAdapter, ProviderSignal

logger = logging.getLogger("ati_evn.enrichment_v2.adapters.pulsedive")

URL = "https://pulsedive.com/api/info.php"


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(min=1, max=8),
    retry=retry_if_exception_type(httpx.RequestError),
    reraise=True,
)
async def _get(params: dict) -> httpx.Response:
    async with httpx.AsyncClient(timeout=15.0) as client:
        return await client.get(URL, params=params)


class PulsediveAdapter(BaseIpAdapter):
    provider_name = "pulsedive"

    async def fetch(self, ip: str) -> ProviderSignal:
        settings = get_settings()
        if not settings.pulsedive_api_key:
            return self._mk_error("PULSEDIVE_API_KEY missing")

        params = {"indicator": ip, "key": settings.pulsedive_api_key, "pretty": 1}
        try:
            resp = await _get(params)
            if resp.status_code == 429:
                return self._mk_error("Rate limited")
            if resp.status_code in (401, 403):
                return self._mk_error(f"Auth failed ({resp.status_code})")
            if resp.status_code == 404:
                return ProviderSignal(
                    provider=self.provider_name,
                    signals={"risk_level": "none", "threat_count": 0, "feed_count": 0},
                    raw_data={"not_tracked": True},
                )
            if resp.status_code >= 400:
                return self._mk_error(f"HTTP {resp.status_code}")
            data = resp.json()
        except Exception as e:
            logger.warning("Pulsedive fetch failed for %s: %s", ip, e)
            return self._mk_error(f"{type(e).__name__}: {str(e)[:100]}")

        if isinstance(data, dict) and data.get("error"):
            return self._mk_error(f"Pulsedive: {data['error'][:100]}")

        risk = (data.get("risk") or "unknown").lower()
        threats = data.get("threats") or []
        feeds = data.get("feeds") or []
        threat_names = [t.get("name") for t in threats[:10] if t.get("name")]
        feed_names = [f.get("name") for f in feeds[:10] if f.get("name")]

        return ProviderSignal(
            provider=self.provider_name,
            signals={
                "risk_level": risk,
                "risk_recommended": data.get("risk_recommended"),
                "threat_count": len(threat_names),
                "feed_count": len(feed_names),
                "threats": threat_names,
                "feeds": feed_names,
                "type": data.get("type"),
            },
            country=None,
            isp=None,
            raw_data={
                "risk": risk,
                "risk_recommended": data.get("risk_recommended"),
                "threats": threat_names,
                "feeds": feed_names,
                "type": data.get("type"),
                "attributes": data.get("attributes") or {},
                "properties": data.get("properties") or {},
            },
        )
