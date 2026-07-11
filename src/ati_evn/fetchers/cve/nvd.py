"""NVD (National Vulnerability Database) CVE fetcher.

Correct API usage (2025+)
-------------------------
- Endpoint: GET https://services.nvd.nist.gov/rest/json/cves/2.0
- Header:   apiKey: <YOUR-API-KEY>   (camelCase, NOT X-Api-Key)
- Rate:     50 req/30s with a key, 5 req/30s without. We sleep 0.6s between
  pages regardless, which keeps us comfortably under the keyed limit.
- Query params for a rolling window:
    lastModStartDate=<ISO8601 with millis + offset>
    lastModEndDate=<ISO8601 with millis + offset>
    resultsPerPage=200
    startIndex=<pagination offset>
  Example timestamp: "2026-07-10T00:00:00.000+00:00"

  We filter on lastModStartDate/lastModEndDate rather than pubStartDate/
  pubEndDate because CPE data is added by NVD analysts several days after
  a CVE is published. Using pubStart gives us fresh CVE IDs with almost no
  product data (~2% CPE yield, verified live). lastMod captures both newly
  published CVEs AND older CVEs that just got their CPE data attached
  (~30-60% CPE yield, verified live), which is what cve_product_map needs.

Reference: https://nvd.nist.gov/developers/vulnerabilities

Response schema (verified by live call)
----------------------------------------
{
  "resultsPerPage": 200, "startIndex": 0, "totalResults": 283,
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2026-15143",
        "published": "2026-07-10T16:16:25.680",
        "lastModified": "2026-07-10T17:49:57.737",
        "descriptions": [{"lang": "en", "value": "..."}],
        "metrics": {
          "cvssMetricV31": [{"cvssData": {"baseScore": 9.3, "baseSeverity": "CRITICAL", ...}}],
          "cvssMetricV30": [...],  # fallback
          "cvssMetricV2":  [...],  # fallback
        },
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-409"}]}],
        "configurations": [
          {"nodes": [{"cpeMatch": [
            {"criteria": "cpe:2.3:a:getgrav:grav:*:*:*:*:*:*:*:*",
             "versionStartIncluding": "1.0.0", "versionEndExcluding": "2.0.0"},
            ...
          ]}]}
        ]
      }
    },
    ...
  ]
}

This fetcher emits TWO distinct artifacts: one RawIOC per CVE (for the
Detection pipeline) plus a separate list of CVE→product rows (for
cve_product_map). We chose to return a tuple[list[RawIOC], list[dict]] from
fetch() rather than adding a second abstract method to IOCFetcher — the CPE
rows are structurally tied 1:1 to this fetch call (same page, same CVE loop)
and every other fetcher would otherwise need a no-op stub for an unused
method. The runner special-cases NVD's return shape.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

import httpx

from ati_evn.fetchers.base import IOCFetcher, RawIOC

logger = logging.getLogger("ati_evn.fetchers.nvd")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 200
PAGE_SLEEP_SECONDS = 0.6

# NVD baseSeverity values line up with our Severity enum already, but be
# defensive in case NVD emits something unexpected.
SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}


def _fmt_iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def _best_metrics(metrics: dict) -> tuple[float | None, str | None, str | None]:
    """Return (baseScore, baseSeverity, vectorString) preferring v3.1 > v3.0 > v2."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key)
        if rows:
            cvss = rows[0].get("cvssData", {})
            return (
                cvss.get("baseScore"),
                cvss.get("baseSeverity"),
                cvss.get("vectorString"),
            )
    return None, None, None


def _extract_cwe_ids(weaknesses: list[dict]) -> list[str]:
    cwe_ids: list[str] = []
    for w in weaknesses or []:
        for desc in w.get("description", []):
            value = desc.get("value")
            if value and value.startswith("CWE-"):
                cwe_ids.append(value)
    return cwe_ids


def _build_version_range(cpe_match: dict) -> str | None:
    parts = []
    if v := cpe_match.get("versionStartIncluding"):
        parts.append(f">={v}")
    if v := cpe_match.get("versionStartExcluding"):
        parts.append(f">{v}")
    if v := cpe_match.get("versionEndIncluding"):
        parts.append(f"<={v}")
    if v := cpe_match.get("versionEndExcluding"):
        parts.append(f"<{v}")
    if not parts:
        return None
    return ", ".join(parts)


def _extract_product_rows(cve_id: str, configurations: list[dict]) -> list[dict]:
    rows: list[dict] = []
    seen: set[tuple[str, str]] = set()

    for config in configurations or []:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                criteria = cpe_match.get("criteria") or ""
                cpe_parts = criteria.split(":")
                # cpe:2.3:a:vendor:product:version:...
                if len(cpe_parts) < 5:
                    continue
                vendor = cpe_parts[3]
                product = cpe_parts[4]
                if not vendor or not product or vendor in ("*", "-") or product in ("*", "-"):
                    continue

                key = (vendor, product)
                version_range = _build_version_range(cpe_match)
                if key in seen and version_range is None:
                    continue
                seen.add(key)

                rows.append({
                    "cve_id": cve_id,
                    "vendor": vendor,
                    "product": product,
                    "version_range": version_range,
                    "source": "nvd",
                })
    return rows


class NVDFetcher(IOCFetcher):
    name = "nvd"
    requires_auth = True

    def is_configured(self) -> bool:
        return bool(self.settings.nvd_api_key)

    async def fetch(self, since_hours: int = 48) -> tuple[list[RawIOC], list[dict]]:
        if not self.is_configured():
            logger.warning("NVD: NVD_API_KEY missing — skipping")
            return [], []

        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=since_hours)
        headers = {"apiKey": self.settings.nvd_api_key}

        raw_iocs: list[RawIOC] = []
        product_rows: list[dict] = []

        start_index = 0
        total_results: int | None = None
        page = 0

        async with await self._http_client(extra_headers=headers) as client:
            while total_results is None or start_index < total_results:
                params = {
                    "lastModStartDate": _fmt_iso(start),
                    "lastModEndDate": _fmt_iso(now),
                    "resultsPerPage": RESULTS_PER_PAGE,
                    "startIndex": start_index,
                }
                try:
                    resp = await client.get(NVD_URL, params=params)
                    resp.raise_for_status()
                    data = resp.json()
                except httpx.HTTPStatusError as e:
                    body = e.response.text[:300]
                    logger.error("NVD HTTP %s: %s", e.response.status_code, body)
                    break
                except (httpx.HTTPError, ValueError) as e:
                    logger.error("NVD transport error: %s", e)
                    break

                total_results = data.get("totalResults", 0)
                vulnerabilities = data.get("vulnerabilities") or []

                for entry in vulnerabilities:
                    cve = entry.get("cve") or {}
                    cve_id = cve.get("id")
                    if not cve_id:
                        continue
                    cve_id = cve_id.upper()

                    descriptions = cve.get("descriptions") or []
                    en_desc = next(
                        (d.get("value") for d in descriptions if d.get("lang") == "en"),
                        None,
                    )

                    base_score, base_severity, vector = _best_metrics(cve.get("metrics") or {})
                    severity_hint = SEVERITY_MAP.get((base_severity or "").upper(), "MEDIUM")

                    metadata = {
                        "cvss_score": base_score,
                        "cvss_vector": vector,
                        "cwe_ids": _extract_cwe_ids(cve.get("weaknesses") or []),
                        "published": cve.get("published"),
                        "lastModified": cve.get("lastModified"),
                    }

                    raw_iocs.append(RawIOC(
                        source=self.name,
                        ioc_type="cve_id",
                        ioc_value=cve_id,
                        raw_text=(en_desc or "")[:500] or None,
                        severity_hint=severity_hint,
                        first_seen=_parse_published(cve.get("published")),
                        metadata=metadata,
                    ))

                    product_rows.extend(
                        _extract_product_rows(cve_id, cve.get("configurations") or [])
                    )

                start_index += RESULTS_PER_PAGE
                page += 1

                if start_index < (total_results or 0):
                    await asyncio.sleep(PAGE_SLEEP_SECONDS)

        logger.info(
            "NVD: fetched %d CVEs (%d product-map rows) across %d page(s), window=%dh",
            len(raw_iocs), len(product_rows), page, since_hours,
        )
        return raw_iocs, product_rows


def _parse_published(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None
