"""ThreatFox (abuse.ch) fetcher.

Correct API usage (2025+)
-------------------------
- Endpoint: POST https://threatfox-api.abuse.ch/api/v1/
- Header:   Auth-Key: <YOUR-AUTH-KEY>   (REQUIRED — abuse.ch enforces since 2024)
- Body:     {"query": "get_iocs", "days": 1..7}

Reference: https://threatfox.abuse.ch/api/  (auth section)

Response schema
---------------
{
  "query_status": "ok",
  "data": [
    {
      "id": "1234",
      "ioc": "1.2.3.4:8080",
      "threat_type": "botnet_cc",
      "threat_type_desc": "...",
      "ioc_type": "ip:port" | "domain" | "url" | "md5_hash" | "sha256_hash" | ...,
      "malware": "win.cobalt_strike",
      "malware_printable": "Cobalt Strike",
      "confidence_level": 50..100,
      "first_seen": "2025-01-15 09:22:00 UTC",
      "reporter": "...",
      "tags": ["exe"]
    },
    ...
  ]
}

Confidence-level → severity hint mapping
----------------------------------------
- >= 90 : HIGH   (confirmed by reporter, multiple observations)
- >= 75 : MEDIUM
- >= 50 : LOW
- <  50 : INFO   (unverified)
"""
from __future__ import annotations

import logging
from datetime import datetime

import httpx

from ati_evn.fetchers.base import IOCFetcher, RawIOC

logger = logging.getLogger("ati_evn.fetchers.threatfox")

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"

# ThreatFox ioc_type → our canonical ioc_type
IOC_TYPE_MAP = {
    "ip:port": "ipv4",              # we split off the port into metadata
    "ip": "ipv4",
    "domain": "domain",
    "url": "url",
    "md5_hash": "md5",
    "sha1_hash": "sha1",
    "sha256_hash": "sha256",
    "email": "email",
}


def _severity_from_confidence(confidence: int | None) -> str:
    if confidence is None:
        return "LOW"
    if confidence >= 90:
        return "HIGH"
    if confidence >= 75:
        return "MEDIUM"
    if confidence >= 50:
        return "LOW"
    return "INFO"


def _parse_first_seen(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        # ThreatFox format: "2025-01-15 09:22:00 UTC"
        return datetime.strptime(s.replace(" UTC", ""), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


class ThreatFoxFetcher(IOCFetcher):
    name = "threatfox"
    requires_auth = True

    def is_configured(self) -> bool:
        return bool(self.settings.abuse_ch_auth_key)

    async def fetch(self, since_hours: int = 24) -> list[RawIOC]:
        if not self.is_configured():
            logger.warning("ThreatFox: ABUSE_CH_AUTH_KEY missing — skipping")
            return []

        # ThreatFox API takes `days` (1 to 7). Ceil hours → days.
        days = max(1, min(7, (since_hours + 23) // 24))
        payload = {"query": "get_iocs", "days": days}

        headers = {"Auth-Key": self.settings.abuse_ch_auth_key}

        async with await self._http_client(extra_headers=headers) as client:
            try:
                resp = await client.post(THREATFOX_URL, json=payload)
                resp.raise_for_status()
                data = resp.json()
            except httpx.HTTPStatusError as e:
                body = e.response.text[:300]
                logger.error("ThreatFox HTTP %s: %s", e.response.status_code, body)
                # Re-raise so callers (fetchers/scheduler.py) see this as a
                # failure rather than an empty-but-successful fetch — an
                # auth error would otherwise silently look like "no new IOCs".
                raise
            except (httpx.HTTPError, ValueError) as e:
                logger.error("ThreatFox transport error: %s", e)
                raise

        if data.get("query_status") != "ok":
            logger.error("ThreatFox query_status=%s data=%s",
                         data.get("query_status"), str(data)[:200])
            return []

        raw_rows = data.get("data") or []
        results: list[RawIOC] = []

        for row in raw_rows:
            ioc_type_raw = (row.get("ioc_type") or "").lower()
            canonical_type = IOC_TYPE_MAP.get(ioc_type_raw)
            if not canonical_type:
                continue

            ioc_value = (row.get("ioc") or "").strip()
            if not ioc_value:
                continue

            metadata: dict = {
                "threatfox_id": row.get("id"),
                "threat_type": row.get("threat_type"),
                "malware": row.get("malware"),
                "malware_printable": row.get("malware_printable"),
                "confidence_level": row.get("confidence_level"),
                "reporter": row.get("reporter"),
                "tags": row.get("tags") or [],
                "reference": row.get("reference"),
            }

            # Split "ip:port" → ip + port in metadata
            if ioc_type_raw == "ip:port" and ":" in ioc_value:
                ip_part, port_part = ioc_value.rsplit(":", 1)
                ioc_value = ip_part.strip()
                metadata["port"] = port_part.strip()

            # URL parsing: normalize + extract host
            if canonical_type == "url":
                # keep original URL as ioc_value; extract host into metadata
                # so domain matching later can find it.
                try:
                    from urllib.parse import urlparse
                    host = urlparse(ioc_value).hostname
                    if host:
                        metadata["host"] = host.lower()
                except Exception:
                    pass

            # Basic IPv4/IPv6 discrimination (very cheap)
            if canonical_type == "ipv4" and ":" in ioc_value and ioc_value.count(":") > 1:
                canonical_type = "ipv6"

            severity = _severity_from_confidence(row.get("confidence_level"))

            desc_bits = [
                row.get("malware_printable"),
                row.get("threat_type_desc"),
            ]
            raw_text = " | ".join(x for x in desc_bits if x)

            results.append(RawIOC(
                source=self.name,
                ioc_type=canonical_type,
                ioc_value=ioc_value.lower(),
                raw_text=raw_text or None,
                severity_hint=severity,
                first_seen=_parse_first_seen(row.get("first_seen")),
                metadata=metadata,
            ))

        logger.info("ThreatFox: fetched %d IOCs (%d raw, %d days window)",
                    len(results), len(raw_rows), days)
        return results
