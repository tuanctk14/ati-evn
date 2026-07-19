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
        "references": [{"url": "https://vendor.example/advisory"}, ...],
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

LLM CPE/CWE inference (inline, gated)
--------------------------------------
For each CVE, if NVD's own configurations/weaknesses leave a gap (missing
CPE and/or CWE) AND the description or a reference URL mentions a vendor
we actually have assets for (llm.cve_filter.should_run_llm), we make ONE
LLM call to fill that gap. This runs inline in fetch() — not a separate
batch job — bounded by an asyncio.Semaphore(settings.llm_max_concurrent)
so a large page of CVEs doesn't fire hundreds of concurrent LLM calls.

fetch() returns a dict with three keys (not the old tuple shape):
    {"raw_iocs": list[RawIOC], "cpe_rows": list[dict], "cwe_rows": list[dict]}
cpe_rows/cwe_rows mix source='nvd' (from CPE/weaknesses) and
source='llm_inferred' (from the LLM gap-fill) rows; the ingest pipeline
upserts both into their respective tables without caring which is which.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

import httpx

from ati_evn.db.queries import load_evn_vendors_lowercase
from ati_evn.fetchers.base import IOCFetcher, RawIOC
from ati_evn.llm.client import LLMClient, LLMError
from ati_evn.llm.cpe_inferrer import infer_missing_metadata
from ati_evn.llm.cve_filter import should_run_llm

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


def _extract_cwe_rows(cve_id: str, weaknesses: list[dict]) -> list[dict]:
    rows: list[dict] = []
    seen: set[str] = set()
    for w in weaknesses or []:
        for desc in w.get("description", []):
            value = desc.get("value")
            if value and value.startswith("CWE-") and value not in seen:
                seen.add(value)
                rows.append({"cve_id": cve_id, "cwe_id": value, "source": "nvd"})
    return rows


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


def _parse_published(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


class NVDFetcher(IOCFetcher):
    name = "nvd"
    requires_auth = True

    def is_configured(self) -> bool:
        return bool(self.settings.nvd_api_key)

    async def _fetch_paginated(self, since_hours: int) -> list[dict]:
        """Return the raw list of NVD `cve` dicts across all pages."""
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=since_hours)
        headers = {"apiKey": self.settings.nvd_api_key}

        cves_raw: list[dict] = []
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
                    # Re-raise rather than silently returning what we have
                    # so far — a 401/403/404 usually means a bad API key,
                    # and callers (e.g. fetchers/scheduler.py) need to see
                    # that as a failure, not an empty-but-successful fetch.
                    raise
                except (httpx.HTTPError, ValueError) as e:
                    logger.error("NVD transport error: %s", e)
                    raise

                total_results = data.get("totalResults", 0)
                vulnerabilities = data.get("vulnerabilities") or []
                cves_raw.extend(entry.get("cve") or {} for entry in vulnerabilities)

                start_index += RESULTS_PER_PAGE
                page += 1

                if start_index < (total_results or 0):
                    await asyncio.sleep(PAGE_SLEEP_SECONDS)

        logger.info("NVD: fetched %d raw CVE entries across %d page(s), window=%dh",
                    len(cves_raw), page, since_hours)
        return cves_raw

    def _build_raw_ioc(self, cve: dict) -> RawIOC | None:
        cve_id = cve.get("id")
        if not cve_id:
            return None
        cve_id = cve_id.upper()

        descriptions = cve.get("descriptions") or []
        en_desc = next((d.get("value") for d in descriptions if d.get("lang") == "en"), None)

        base_score, base_severity, vector = _best_metrics(cve.get("metrics") or {})
        severity_hint = SEVERITY_MAP.get((base_severity or "").upper(), "MEDIUM")

        metadata = {
            "cvss_score": base_score,
            "cvss_vector": vector,
            "cwe_ids": [row["cwe_id"] for row in _extract_cwe_rows(cve_id, cve.get("weaknesses") or [])],
            "published": cve.get("published"),
            "lastModified": cve.get("lastModified"),
            "references": cve.get("references") or [],
        }

        return RawIOC(
            source=self.name,
            ioc_type="cve_id",
            ioc_value=cve_id,
            raw_text=(en_desc or "")[:500] or None,
            severity_hint=severity_hint,
            first_seen=_parse_published(cve.get("published")),
            metadata=metadata,
        )

    async def _process_one(
        self, cve: dict, evn_vendors: set[str],
        llm_client: LLMClient | None, sem: asyncio.Semaphore,
    ) -> dict:
        cve_id = (cve.get("id") or "").upper()
        raw_ioc = self._build_raw_ioc(cve)

        nvd_cpe_rows = _extract_product_rows(cve_id, cve.get("configurations") or [])
        nvd_cwe_rows = _extract_cwe_rows(cve_id, cve.get("weaknesses") or [])

        if not cve_id or raw_ioc is None:
            return {"raw_ioc": None, "cpe_rows": [], "cwe_rows": []}

        descriptions = cve.get("descriptions") or []
        description = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "") or ""
        references = cve.get("references") or []

        has_cpe = bool(nvd_cpe_rows)
        has_cwe = bool(nvd_cwe_rows)

        should, reason = should_run_llm(
            has_cpe=has_cpe, has_cwe=has_cwe,
            description=description, references=references,
            evn_vendors=evn_vendors,
        )

        llm_cpe_rows: list[dict] = []
        llm_cwe_rows: list[dict] = []

        if should and llm_client is not None and llm_client.is_configured():
            logger.info("LLM inference for %s: %s", cve_id, reason)
            async with sem:
                try:
                    meta = await infer_missing_metadata(
                        llm_client, cve_id, description, references,
                        need_cpe=not has_cpe, need_cwe=not has_cwe,
                        context_hint_vendors=list(evn_vendors),
                    )
                    min_conf = self.settings.llm_cpe_min_confidence
                    if not has_cpe:
                        llm_cpe_rows = [
                            {
                                "cve_id": cve_id, "vendor": e.vendor, "product": e.product,
                                "version_range": e.version_range, "source": "llm_inferred",
                                "confidence": e.confidence, "reasoning": e.reasoning,
                            }
                            for e in meta.cpe_entries if e.confidence >= min_conf
                        ]
                    if not has_cwe:
                        llm_cwe_rows = [
                            {
                                "cve_id": cve_id, "cwe_id": c, "source": "llm_inferred",
                                "confidence": 0.7, "reasoning": meta.reasoning,
                            }
                            for c in meta.cwe_ids
                        ]
                except LLMError as e:
                    logger.warning("LLM failed for %s: %s", cve_id, e)
        elif not should:
            logger.debug("Skip LLM for %s: %s", cve_id, reason)

        return {
            "raw_ioc": raw_ioc,
            "cpe_rows": nvd_cpe_rows + llm_cpe_rows,
            "cwe_rows": nvd_cwe_rows + llm_cwe_rows,
        }

    async def fetch(self, since_hours: int = 48) -> dict:
        if not self.is_configured():
            logger.warning("NVD: NVD_API_KEY missing — skipping")
            return {"raw_iocs": [], "cpe_rows": [], "cwe_rows": []}

        evn_vendors = await load_evn_vendors_lowercase()
        llm_client = LLMClient(self.settings) if self.settings.openai_api_key else None
        sem = asyncio.Semaphore(self.settings.llm_max_concurrent)

        cves_raw = await self._fetch_paginated(since_hours)

        results: list[dict] = []
        tasks = [self._process_one(cve, evn_vendors, llm_client, sem) for cve in cves_raw]
        for i, task in enumerate(asyncio.as_completed(tasks), 1):
            results.append(await task)
            if i % 100 == 0:
                logger.info("NVD process progress: %d/%d", i, len(cves_raw))

        raw_iocs = [r["raw_ioc"] for r in results if r["raw_ioc"] is not None]
        cpe_rows = [row for r in results for row in r["cpe_rows"]]
        cwe_rows = [row for r in results for row in r["cwe_rows"]]

        llm_cpe_count = sum(1 for row in cpe_rows if row.get("source") == "llm_inferred")
        llm_cwe_count = sum(1 for row in cwe_rows if row.get("source") == "llm_inferred")
        logger.info(
            "NVD: fetched %d CVEs, %d CPE rows (%d llm), %d CWE rows (%d llm), window=%dh",
            len(raw_iocs), len(cpe_rows), llm_cpe_count, len(cwe_rows), llm_cwe_count, since_hours,
        )

        return {"raw_iocs": raw_iocs, "cpe_rows": cpe_rows, "cwe_rows": cwe_rows}
