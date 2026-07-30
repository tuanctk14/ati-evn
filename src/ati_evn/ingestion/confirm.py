"""Workflow to materialize an IngestionSession into real system state.

Steps:
  1. Load session, validate status=pending
  2. Bulk-create Detection rows for each IOC (source='analyst_ingested',
     metadata includes article_url + ingestion_session_id)
  3. Auto-fetch missing CVE from NVD (parallel batch, 10 concurrent)
  4. Bulk-create Detection rows for each CVE (source='analyst_ingested')
  5. Trigger scoped matcher — only new Detection IDs from this session
  6. Update session status=confirmed, populate detection_ids_created +
     finding_ids_created
  7. Return stats dict
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import select

from ati_evn.db.models import (
    CveProductMap,
    Detection,
    DetectionStatus,
    IngestionSession,
    Severity,
)
from ati_evn.db.session import async_session
from ati_evn.fetchers.cve.nvd_single import fetch_single_cve
from ati_evn.match.customer_router import route_detections

logger = logging.getLogger("ati_evn.ingestion.confirm")

CVE_FETCH_CONCURRENCY = 10


def _confidence_to_severity(confidence: float) -> Severity:
    """Map LLM confidence to default severity for ingested IOCs."""
    if confidence >= 0.85:
        return Severity.HIGH
    if confidence >= 0.6:
        return Severity.MEDIUM
    return Severity.LOW


async def _fetch_missing_cves(cve_ids: list[str]) -> dict[str, bool]:
    """Fetch each CVE if not already in cve_product_map. Return dict
    cve_id -> success bool (True also for CVEs already present)."""
    if not cve_ids:
        return {}

    async with async_session() as session:
        existing = set()
        rows = await session.execute(
            select(CveProductMap.cve_id).where(CveProductMap.cve_id.in_(cve_ids))
        )
        existing.update(r[0] for r in rows)

    missing = [c for c in cve_ids if c not in existing]
    if not missing:
        return {c: True for c in cve_ids}

    logger.info("Auto-fetching %d missing CVEs (of %d total)", len(missing), len(cve_ids))

    sem = asyncio.Semaphore(CVE_FETCH_CONCURRENCY)

    async def _one(cid: str) -> tuple[str, bool]:
        async with sem:
            try:
                ok = await fetch_single_cve(cid)
                return cid, bool(ok)
            except Exception as e:
                logger.warning("Auto-fetch %s failed: %s", cid, e)
                return cid, False

    results = await asyncio.gather(*[_one(c) for c in missing])
    return {c: r for c, r in results} | {c: True for c in existing}


async def confirm_ingestion(session_id: int, analyst_username: str) -> dict:
    """Confirm an ingestion session — creates Detections, auto-fetches
    missing CVEs, runs a scoped matcher pass, and returns a stats dict."""
    async with async_session() as session:
        ingest = await session.get(IngestionSession, session_id)
        if not ingest:
            return {"error": f"Session #{session_id} not found"}
        if ingest.status != "pending":
            return {"error": f"status={ingest.status}, only pending confirmable"}

        data = ingest.extracted_data or {}
        iocs = data.get("iocs") or []
        cves = data.get("cves") or []
        confidence = float(data.get("confidence") or 0.5)
        article_url = ingest.source_url or ""
        source_filename = ingest.source_filename

        severity = _confidence_to_severity(confidence)
        malware_str = ", ".join(data.get("malware_families") or []) or None
        attribution = data.get("attribution_hints") or None

        new_detection_ids: list[int] = []
        for ioc in iocs:
            det = Detection(
                source="analyst_ingested",
                ioc_type=ioc["type"],
                ioc_value=ioc["value"].lower().strip(),
                raw_text=ioc.get("context") or "",
                severity=severity,
                status=DetectionStatus.NEW,
                metadata_={
                    "ingestion_session_id": session_id,
                    "article_url": article_url,
                    "article_filename": source_filename,
                    "extraction_confidence": confidence,
                    "context": ioc.get("context") or "",
                    "malware_printable": malware_str,
                    "attribution": attribution,
                },
            )
            session.add(det)
            await session.flush()
            new_detection_ids.append(det.id)
        await session.commit()

    # Auto-fetch missing CVEs — outside the session so NVD HTTP calls
    # don't hold a DB connection open.
    cve_ids = [c["id"] for c in cves]
    cve_fetch_results = await _fetch_missing_cves(cve_ids)
    cve_fetch_ok = [c for c, ok in cve_fetch_results.items() if ok]
    cve_fetch_fail = [c for c, ok in cve_fetch_results.items() if not ok]

    async with async_session() as session:
        for cve in cves:
            if cve["id"] not in cve_fetch_ok:
                continue
            det = Detection(
                source="analyst_ingested",
                ioc_type="cve_id",
                ioc_value=cve["id"].lower(),
                raw_text=cve.get("context") or "",
                severity=severity,
                status=DetectionStatus.NEW,
                metadata_={
                    "ingestion_session_id": session_id,
                    "article_url": article_url,
                    "article_filename": source_filename,
                    "extraction_confidence": confidence,
                    "context": cve.get("context") or "",
                },
            )
            session.add(det)
            await session.flush()
            new_detection_ids.append(det.id)
        await session.commit()

    findings_created = 0
    findings_merged = 0
    if new_detection_ids:
        try:
            async with async_session() as session:
                match_stats = await route_detections(
                    session, detection_ids=new_detection_ids,
                )
            findings_created = match_stats.findings_created
            findings_merged = match_stats.findings_merged
        except Exception as e:
            logger.exception("Matcher failed for ingested detections: %s", e)

    async with async_session() as session:
        f_stmt = (
            select(Detection.finding_id)
            .where(
                Detection.id.in_(new_detection_ids),
                Detection.finding_id.is_not(None),
            )
            .distinct()
        )
        new_finding_ids = list({r[0] for r in await session.execute(f_stmt) if r[0]})

        ingest = await session.get(IngestionSession, session_id)
        ingest.status = "confirmed"
        ingest.confirmed_at = datetime.now(timezone.utc)
        ingest.detection_ids_created = new_detection_ids
        ingest.finding_ids_created = new_finding_ids
        await session.commit()

    stats = {
        "session_id": session_id,
        "iocs_ingested": len(iocs),
        "cves_ingested": len(cve_fetch_ok),
        "cve_ids": cve_fetch_ok,
        "cves_fetch_failed": cve_fetch_fail,
        "detections_created": len(new_detection_ids),
        "findings_created": len(new_finding_ids),
        "finding_ids": new_finding_ids,
    }
    logger.info("Ingestion #%d confirmed: %s", session_id, stats)
    return stats
