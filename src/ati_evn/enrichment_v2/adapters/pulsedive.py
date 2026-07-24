"""Pulsedive info.php per-IP adapter.

Endpoint: /api/info.php?indicator={ip}&key={key}
Returns: risk level (none/low/medium/high/critical) + threats + feeds

Verdict from risk level string mapping.
"""
from __future__ import annotations

import logging

import httpx

from ati_evn.config import get_settings
from ati_evn.enrichment_v2.adapters._base import BaseIpAdapter, ProviderVerdict, Verdict
from ati_evn.enrichment_v2.config import get_provider_config

logger = logging.getLogger("ati_evn.enrichment_v2.adapters.pulsedive")

URL = "https://pulsedive.com/api/info.php"

RISK_LEVEL_ORDER = ["none", "unknown", "low", "medium", "high", "critical"]
RISK_SCORE_MAP = {
    "none": 0, "unknown": 0, "low": 25,
    "medium": 50, "high": 75, "critical": 100,
}


class PulsediveAdapter(BaseIpAdapter):
    provider_name = "pulsedive"

    async def fetch(self, ip: str) -> ProviderVerdict:
        settings = get_settings()
        if not settings.pulsedive_api_key:
            return self._mk_error("PULSEDIVE_API_KEY missing")

        params = {"indicator": ip, "key": settings.pulsedive_api_key, "pretty": 1}
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(URL, params=params)
            if resp.status_code == 429:
                return self._mk_error("Rate limited")
            if resp.status_code in (401, 403):
                return self._mk_error(f"Auth failed ({resp.status_code})")
            if resp.status_code == 404:
                return ProviderVerdict(
                    provider=self.provider_name,
                    normalized_score=0.0,
                    verdict="benign",
                    confidence=0.4,
                    raw_data={"not_tracked": True},
                )
            if resp.status_code >= 400:
                return self._mk_error(f"HTTP {resp.status_code}")
            data = resp.json()
        except Exception as e:
            return self._mk_error(f"{type(e).__name__}: {str(e)[:100]}")

        if isinstance(data, dict) and data.get("error"):
            return self._mk_error(f"Pulsedive: {data['error'][:100]}")

        risk = (data.get("risk") or "unknown").lower()
        threats = data.get("threats") or []
        feeds = data.get("feeds") or []

        verdict, confidence = self._map_verdict(risk)
        norm_score = RISK_SCORE_MAP.get(risk, 0)

        threat_names = [t.get("name") for t in threats[:10] if t.get("name")]
        feed_names = [f.get("name") for f in feeds[:10] if f.get("name")]

        return ProviderVerdict(
            provider=self.provider_name,
            normalized_score=float(norm_score),
            verdict=verdict,
            confidence=confidence,
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

    def _map_verdict(self, risk: str) -> tuple[Verdict, float]:
        cfg = get_provider_config("pulsedive")
        mal_level = cfg.get("malicious_level", "medium")
        susp_level = cfg.get("suspicious_level", "low")

        try:
            risk_rank = RISK_LEVEL_ORDER.index(risk)
            mal_rank = RISK_LEVEL_ORDER.index(mal_level)
            susp_rank = RISK_LEVEL_ORDER.index(susp_level)
        except ValueError:
            return "unknown", 0.3

        if risk_rank >= mal_rank:
            return "malicious", 0.7
        elif risk_rank >= susp_rank:
            return "suspicious", 0.5
        else:
            return "benign", 0.5
