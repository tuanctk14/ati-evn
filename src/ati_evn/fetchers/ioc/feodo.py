"""Feodo Tracker (abuse.ch) fetcher — botnet C&C IP blocklist.

Correct API usage (2025+)
-------------------------
- Endpoint: GET https://feodotracker.abuse.ch/downloads/ipblocklist.json
- Header:   Auth-Key: <YOUR-AUTH-KEY>   (same key as ThreatFox/MalwareBazaar/
  URLhaus). Verified: the endpoint returns 200 both with and without the
  header at time of writing, but we always send it for forward compatibility
  with abuse.ch's auth rollout.

Reference: https://feodotracker.abuse.ch/blocklist/

Response schema — JSON array, no wrapper object
------------------------------------------------
[
  {
    "ip_address": "162.243.103.246", "port": 8080, "status": "online" | "offline",
    "hostname": null, "as_number": 14061, "as_name": "DIGITALOCEAN-ASN",
    "country": "US", "first_seen": "2022-06-04 21:24:53",
    "last_online": "2026-03-07", "malware": "Emotet"
  },
  ...
]

This feed only lists CURRENTLY tracked C&C servers (not a rolling 24h window),
so `since_hours` is accepted for interface consistency but not used to filter
— every row is either online or recently seen offline. We only emit rows
with status == "online" since those are confirmed-active C&C.

Endpoint choice (verified 2026-07-11 by live call)
---------------------------------------------------
abuse.ch also publishes ipblocklist_recommended.json and
ipblocklist_aggressive.json. We checked both: "recommended" is a *subset* of
the standard list (1 entry vs. our 5, same single online IP) — not a larger
feed as its name might suggest — and "aggressive" 404s (not a live endpoint).
Feodo Tracker's total tracked C&C population is simply small right now
(low Emotet/Qakbot activity), so a handful of entries is the correct,
non-buggy result. We keep the standard endpoint since it strictly contains
the most rows of the three.
"""
from __future__ import annotations

import logging
from datetime import datetime

import httpx

from ati_evn.fetchers.base import IOCFetcher, RawIOC

logger = logging.getLogger("ati_evn.fetchers.feodo")

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"


def _parse_first_seen(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


class FeodoFetcher(IOCFetcher):
    name = "feodo"
    requires_auth = True

    def is_configured(self) -> bool:
        return bool(self.settings.abuse_ch_auth_key)

    async def fetch(self, since_hours: int = 24) -> list[RawIOC]:
        if not self.is_configured():
            logger.warning("Feodo: ABUSE_CH_AUTH_KEY missing — skipping")
            return []

        headers = {"Auth-Key": self.settings.abuse_ch_auth_key}

        async with await self._http_client(extra_headers=headers) as client:
            try:
                resp = await self._get(client, FEODO_URL)
                resp.raise_for_status()
                data = resp.json()
            except httpx.HTTPStatusError as e:
                body = e.response.text[:300]
                logger.error("Feodo HTTP %s: %s", e.response.status_code, body)
                # Re-raise so callers (fetchers/scheduler.py) see this as a
                # failure rather than an empty-but-successful fetch.
                raise
            except (httpx.HTTPError, ValueError) as e:
                logger.error("Feodo transport error: %s", e)
                raise

        if not isinstance(data, list):
            logger.error("Feodo: unexpected response shape: %s", str(data)[:200])
            return []

        results: list[RawIOC] = []

        for row in data:
            if row.get("status") != "online":
                continue

            ip_value = (row.get("ip_address") or "").strip()
            if not ip_value:
                continue

            metadata: dict = {
                "port": row.get("port"),
                "malware": row.get("malware"),
                "country": row.get("country"),
                "as_number": row.get("as_number"),
                "as_name": row.get("as_name"),
                "hostname": row.get("hostname"),
            }

            results.append(RawIOC(
                source=self.name,
                ioc_type="ipv4",
                ioc_value=ip_value.lower(),
                raw_text=row.get("malware"),
                severity_hint="HIGH",
                first_seen=_parse_first_seen(row.get("first_seen")),
                metadata=metadata,
            ))

        logger.info("Feodo: fetched %d online C&C IOCs (%d raw rows)", len(results), len(data))
        return results
