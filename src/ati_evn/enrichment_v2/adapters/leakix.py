"""LeakIX per-IP adapter.

Endpoint: /host/{ip} with api-key header.
Returns: host with Services + Leaks arrays. Each entry has an
'event_type' field.

Verdict from event types:
  Any event_type in malicious_event_types -> malicious
  Any event exists at all                 -> suspicious (default)
  No events                               -> benign
"""
from __future__ import annotations

import logging

import httpx

from ati_evn.config import get_settings
from ati_evn.enrichment_v2.adapters._base import BaseIpAdapter, ProviderVerdict, Verdict
from ati_evn.enrichment_v2.config import get_provider_config

logger = logging.getLogger("ati_evn.enrichment_v2.adapters.leakix")

URL_TEMPLATE = "https://leakix.net/host/{ip}"


class LeakIXAdapter(BaseIpAdapter):
    provider_name = "leakix"

    async def fetch(self, ip: str) -> ProviderVerdict:
        settings = get_settings()
        if not settings.leakix_api_key:
            return self._mk_error("LEAKIX_API_KEY missing")

        headers = {"api-key": settings.leakix_api_key, "Accept": "application/json"}
        url = URL_TEMPLATE.format(ip=ip)

        try:
            async with httpx.AsyncClient(timeout=15.0, headers=headers) as client:
                resp = await client.get(url)
            if resp.status_code in (401, 403):
                return self._mk_error(f"Auth failed ({resp.status_code})")
            if resp.status_code == 404:
                return ProviderVerdict(
                    provider=self.provider_name,
                    normalized_score=0.0,
                    verdict="benign",
                    confidence=0.5,
                    raw_data={"no_data": True},
                )
            if resp.status_code >= 400:
                return self._mk_error(f"HTTP {resp.status_code}")
            data = resp.json()
        except Exception as e:
            return self._mk_error(f"{type(e).__name__}: {str(e)[:100]}")

        services = data.get("Services") or data.get("services") or []
        leaks = data.get("Leaks") or data.get("leaks") or []
        all_events = list(services) + list(leaks)

        event_types = set()
        for evt in all_events:
            et = evt.get("event_type") or evt.get("type")
            if et:
                event_types.add(et.lower())

        verdict, confidence = self._map_verdict(event_types, len(all_events))

        if not all_events:
            norm_score = 0.0
        else:
            cfg = get_provider_config("leakix")
            malicious_types = set(t.lower() for t in (cfg.get("malicious_event_types") or []))
            if event_types & malicious_types:
                norm_score = min(90.0, 60.0 + len(all_events) * 5)
            else:
                norm_score = min(50.0, 20.0 + len(all_events) * 3)

        return ProviderVerdict(
            provider=self.provider_name,
            normalized_score=norm_score,
            verdict=verdict,
            confidence=confidence,
            country=(data.get("country") or "")[:80] or None,
            isp=None,
            raw_data={
                "services_count": len(services),
                "leaks_count": len(leaks),
                "event_types": sorted(event_types)[:20],
                "services_summary": [
                    {
                        "port": s.get("port"),
                        "protocol": s.get("protocol"),
                        "event_type": s.get("event_type") or s.get("type"),
                        "summary": (s.get("summary") or "")[:200],
                    }
                    for s in services[:5]
                ],
                "leaks_summary": [
                    {
                        "event_type": l.get("event_type") or l.get("type"),
                        "summary": (l.get("summary") or "")[:200],
                    }
                    for l in leaks[:5]
                ],
            },
        )

    def _map_verdict(self, event_types: set, event_count: int) -> tuple[Verdict, float]:
        cfg = get_provider_config("leakix")
        malicious_types = set(t.lower() for t in (cfg.get("malicious_event_types") or []))
        susp_on_any = cfg.get("suspicious_on_any_event", True)

        if event_types & malicious_types:
            return "malicious", 0.8
        elif event_count > 0 and susp_on_any:
            return "suspicious", 0.6
        else:
            return "benign", 0.5
