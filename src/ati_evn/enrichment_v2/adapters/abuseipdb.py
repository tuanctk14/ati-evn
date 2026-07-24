"""AbuseIPDB adapter.

Verdict logic:
  abuseConfidenceScore >= malicious_score  -> malicious
  abuseConfidenceScore >= suspicious_score -> suspicious
  else                                     -> benign

Confidence: proportional to totalReports (log-scale) -- more reports
means more evidence.
"""
from __future__ import annotations

import logging
import math

import httpx

from ati_evn.config import get_settings
from ati_evn.enrichment_v2.adapters._base import BaseIpAdapter, ProviderVerdict, Verdict
from ati_evn.enrichment_v2.config import get_provider_config

logger = logging.getLogger("ati_evn.enrichment_v2.adapters.abuseipdb")

URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBAdapter(BaseIpAdapter):
    provider_name = "abuseipdb"

    async def fetch(self, ip: str) -> ProviderVerdict:
        settings = get_settings()
        if not settings.abuseipdb_api_key:
            return self._mk_error("ABUSEIPDB_API_KEY missing")

        headers = {"Key": settings.abuseipdb_api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        try:
            async with httpx.AsyncClient(timeout=10.0, headers=headers) as client:
                resp = await client.get(URL, params=params)
            if resp.status_code == 429:
                return self._mk_error("Rate limited (quota exceeded)")
            if resp.status_code == 401:
                return self._mk_error("Auth failed (401)")
            if resp.status_code >= 400:
                return self._mk_error(f"HTTP {resp.status_code}")
            data = resp.json().get("data") or {}
        except Exception as e:
            return self._mk_error(f"{type(e).__name__}: {str(e)[:100]}")

        score = int(data.get("abuseConfidenceScore") or 0)
        total_reports = int(data.get("totalReports") or 0)

        verdict, confidence = self._map_verdict(score, total_reports)

        return ProviderVerdict(
            provider=self.provider_name,
            normalized_score=float(score),
            verdict=verdict,
            confidence=confidence,
            country=(data.get("countryCode") or "")[:80] or None,
            isp=(data.get("isp") or "")[:200] or None,
            raw_data={
                "abuse_confidence": score,
                "total_reports": total_reports,
                "usage_type": data.get("usageType"),
                "is_tor": bool(data.get("isTor")),
                "last_reported": data.get("lastReportedAt"),
                "hostnames": data.get("hostnames") or [],
                "domain": data.get("domain"),
            },
        )

    def _map_verdict(self, score: int, total_reports: int) -> tuple[Verdict, float]:
        cfg = get_provider_config("abuseipdb")
        mal_threshold = cfg.get("malicious_score", 50)
        susp_threshold = cfg.get("suspicious_score", 25)

        if score >= mal_threshold:
            verdict: Verdict = "malicious"
        elif score >= susp_threshold:
            verdict = "suspicious"
        else:
            verdict = "benign"

        if total_reports == 0:
            confidence = 0.5
        else:
            confidence = min(1.0, 0.5 + math.log10(total_reports + 1) / 4.0)

        return verdict, confidence
