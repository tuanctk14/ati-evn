"""VirusTotal adapter -- IP address lookup.

Verdict logic:
  malicious engines >= malicious_engines  -> malicious
  malicious engines >= suspicious_engines -> suspicious
  else                                    -> benign

Confidence: high when many engines respond (total_engines).
"""
from __future__ import annotations

import logging

import httpx

from ati_evn.config import get_settings
from ati_evn.enrichment_v2.adapters._base import BaseIpAdapter, ProviderVerdict, Verdict
from ati_evn.enrichment_v2.config import get_provider_config

logger = logging.getLogger("ati_evn.enrichment_v2.adapters.virustotal")

BASE = "https://www.virustotal.com/api/v3"


class VirusTotalAdapter(BaseIpAdapter):
    provider_name = "virustotal"

    async def fetch(self, ip: str) -> ProviderVerdict:
        settings = get_settings()
        if not settings.virustotal_api_key:
            return self._mk_error("VIRUSTOTAL_API_KEY missing")

        headers = {"x-apikey": settings.virustotal_api_key}
        url = f"{BASE}/ip_addresses/{ip}"

        try:
            async with httpx.AsyncClient(timeout=12.0, headers=headers) as client:
                resp = await client.get(url)
            if resp.status_code == 429:
                return self._mk_error("Rate limited (VT quota: 4/min, 500/day)")
            if resp.status_code == 401:
                return self._mk_error("Auth failed (401)")
            if resp.status_code == 404:
                return ProviderVerdict(
                    provider=self.provider_name,
                    normalized_score=0.0,
                    verdict="unknown",
                    confidence=0.3,
                    raw_data={"not_found": True},
                )
            if resp.status_code >= 400:
                return self._mk_error(f"HTTP {resp.status_code}")
            attrs = resp.json().get("data", {}).get("attributes", {})
        except Exception as e:
            return self._mk_error(f"{type(e).__name__}: {str(e)[:100]}")

        stats = attrs.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        harmless = int(stats.get("harmless") or 0)
        undetected = int(stats.get("undetected") or 0)
        total = malicious + suspicious + harmless + undetected

        verdict, confidence = self._map_verdict(malicious, suspicious, total)

        if total > 0:
            norm_score = ((malicious + suspicious * 0.5) / total) * 100
        else:
            norm_score = 0.0

        return ProviderVerdict(
            provider=self.provider_name,
            normalized_score=norm_score,
            verdict=verdict,
            confidence=confidence,
            country=(attrs.get("country") or "")[:80] or None,
            isp=(attrs.get("as_owner") or "")[:200] or None,
            raw_data={
                "malicious_engines": malicious,
                "suspicious_engines": suspicious,
                "harmless_engines": harmless,
                "undetected_engines": undetected,
                "total_engines": total,
                "reputation": attrs.get("reputation"),
                "as_owner": attrs.get("as_owner"),
                "asn": attrs.get("asn"),
                "network": attrs.get("network"),
                "tags": attrs.get("tags") or [],
                "categories": attrs.get("categories") or {},
            },
        )

    def _map_verdict(self, malicious: int, suspicious: int, total: int) -> tuple[Verdict, float]:
        cfg = get_provider_config("virustotal")
        mal_threshold = cfg.get("malicious_engines", 5)
        susp_threshold = cfg.get("suspicious_engines", 1)

        if malicious >= mal_threshold:
            verdict: Verdict = "malicious"
        elif malicious >= susp_threshold or suspicious >= 3:
            verdict = "suspicious"
        elif total > 0:
            verdict = "benign"
        else:
            verdict = "unknown"

        if total >= 40:
            confidence = 0.9
        elif total >= 20:
            confidence = 0.7
        elif total >= 10:
            confidence = 0.5
        else:
            confidence = 0.3

        return verdict, confidence
