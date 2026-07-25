"""LeakIX per-IP adapter. ProviderSignal only, no scoring.

Endpoint: /host/{ip} with api-key header.
Returns: host with Services + Leaks arrays. Each entry has an
'event_type' field.

Scoring/verdict determination lives in enrichment_v2/scoring.py
(ScoringEngine), driven by enrichment_config.yaml.

Note: the malicious-event-type list is read from providers[leakix] in
config (same list the ScoringEngine uses for verdict determination),
because it defines *what to count*, not *how to score*. Counting the
number of malicious-typed events is field extraction, not scoring --
the composite formula in scoring.py decides how that count affects
the score.
"""
from __future__ import annotations

import logging

import httpx

from ati_evn.config import get_settings
from ati_evn.enrichment_v2.adapters._base import BaseIpAdapter, ProviderSignal
from ati_evn.enrichment_v2.config import get_provider_config

logger = logging.getLogger("ati_evn.enrichment_v2.adapters.leakix")

URL_TEMPLATE = "https://leakix.net/host/{ip}"


class LeakIXAdapter(BaseIpAdapter):
    provider_name = "leakix"

    async def fetch(self, ip: str) -> ProviderSignal:
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
                return ProviderSignal(
                    provider=self.provider_name,
                    signals={"services_count": 0, "leaks_count": 0, "malicious_event_types_count": 0},
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

        mal_types_count = self._count_malicious_events(event_types)

        return ProviderSignal(
            provider=self.provider_name,
            signals={
                "services_count": len(services),
                "leaks_count": len(leaks),
                "event_types": sorted(event_types)[:20],
                "malicious_event_types_count": mal_types_count,
            },
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

    def _count_malicious_events(self, event_types: set) -> int:
        cfg = get_provider_config(self.provider_name)
        mal_set = set(t.lower() for t in (cfg.get("malicious_event_types") or []))
        return len(event_types & mal_set)
