"""URLhaus (abuse.ch) fetcher — malicious URL feed.

Correct API usage (2025+) — VERIFIED BY LIVE CALL, differs from initial spec
-----------------------------------------------------------------------------
The spec assumed `POST /v1/urls/recent/` with a `{"query": "get_urls", ...}`
body (matching ThreatFox/MalwareBazaar style). A live call showed that
returns 405 with `{"query_status": "http_get_expected"}`. The actual contract
for this specific endpoint is a plain GET with no body/params:

- Endpoint: GET https://urlhaus-api.abuse.ch/v1/urls/recent/
- Header:   Auth-Key: <YOUR-AUTH-KEY>   (same key as ThreatFox/MalwareBazaar/
  Feodo)
- No query params — returns the full "recent" window as-is (~600-700 URLs at
  time of writing, no `limit` param supported by this endpoint).

Reference: https://urlhaus-api.abuse.ch/  ("Recent URLs" section)

Response schema
---------------
{
  "query_status": "ok",
  "urls": [
    {
      "id": "3885118", "url": "https://.../?ublib=...", "url_status": "offline" | "online",
      "host": "xb7ea3kq.betturkey.bet", "date_added": "2026-07-11 15:31:18 UTC",
      "threat": "malware_download", "reporter": "anonymous", "larted": "false",
      "tags": ["ClearFake", "mac-0x68dc", "macOS"]
    },
    ...
  ]
}
"""
from __future__ import annotations

import logging
from datetime import datetime

import httpx

from ati_evn.fetchers.base import IOCFetcher, RawIOC

logger = logging.getLogger("ati_evn.fetchers.urlhaus")

URLHAUS_RECENT_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"


def _parse_date_added(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.strptime(s.replace(" UTC", ""), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


class URLhausFetcher(IOCFetcher):
    name = "urlhaus"
    requires_auth = True

    def is_configured(self) -> bool:
        return bool(self.settings.abuse_ch_auth_key)

    async def fetch(self, since_hours: int = 24) -> list[RawIOC]:
        if not self.is_configured():
            logger.warning("URLhaus: ABUSE_CH_AUTH_KEY missing — skipping")
            return []

        headers = {"Auth-Key": self.settings.abuse_ch_auth_key}

        async with await self._http_client(extra_headers=headers) as client:
            try:
                resp = await client.get(URLHAUS_RECENT_URL)
                resp.raise_for_status()
                data = resp.json()
            except httpx.HTTPStatusError as e:
                body = e.response.text[:300]
                logger.error("URLhaus HTTP %s: %s", e.response.status_code, body)
                # Re-raise so callers (fetchers/scheduler.py) see this as a
                # failure rather than an empty-but-successful fetch.
                raise
            except (httpx.HTTPError, ValueError) as e:
                logger.error("URLhaus transport error: %s", e)
                raise

        if data.get("query_status") != "ok":
            logger.error("URLhaus query_status=%s data=%s",
                         data.get("query_status"), str(data)[:200])
            return []

        raw_rows = data.get("urls") or []
        results: list[RawIOC] = []

        for row in raw_rows:
            url_value = (row.get("url") or "").strip()
            if not url_value:
                continue

            status = row.get("url_status")
            severity = "HIGH" if status == "online" else "MEDIUM"

            metadata: dict = {
                "threat": row.get("threat"),
                "tags": row.get("tags") or [],
                "larted": row.get("larted"),
                "host": row.get("host"),
                "date_added": row.get("date_added"),
            }

            results.append(RawIOC(
                source=self.name,
                ioc_type="url",
                ioc_value=url_value.lower(),
                raw_text=row.get("threat"),
                severity_hint=severity,
                first_seen=_parse_date_added(row.get("date_added")),
                metadata=metadata,
            ))

        logger.info("URLhaus: fetched %d IOCs (%d raw rows)", len(results), len(raw_rows))
        return results
