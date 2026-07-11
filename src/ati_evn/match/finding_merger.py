"""Detection -> Finding / ProbableExposure merge.

Findings are deduplicated on (customer_id, ioc_type, ioc_value) via the
`uq_finding_customer_ioc` unique constraint. Repeated detections of the same
IOC for the same customer roll into the same Finding: source_count bumps,
sources[] accumulates (deduped), last_seen advances, and severity only ever
goes UP (a later, lower-severity sighting must never quietly downgrade an
existing Finding — that would hide an already-known risk from an analyst).

CVE matches where the match strategy could not confirm version membership
(`MatchResult.is_probable=True`) create a ProbableExposure instead of a
Finding — we're not confident enough to alert on it as a real Finding yet.
"""
from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ati_evn.db.models import Detection, Finding, ProbableExposure, Severity
from ati_evn.match.strategies import MatchResult

logger = logging.getLogger("ati_evn.match.finding_merger")

_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _short(value: str, length: int = 40) -> str:
    value = value.strip()
    return value if len(value) <= length else value[: length - 3] + "..."


def _build_title(severity: Severity, ioc_type: str, ioc_value: str, asset_value: str) -> str:
    return f"{severity.value} {ioc_type} {_short(ioc_value)} detected on {_short(asset_value, 60)}"


async def upsert_finding(
    session: AsyncSession, det: Detection, match: MatchResult, severity: Severity,
) -> Finding:
    """Idempotent on (customer_id, ioc_type, ioc_value). Never downgrades severity."""
    result = await session.execute(
        select(Finding).where(
            Finding.customer_id == match.customer_id,
            Finding.ioc_type == det.ioc_type,
            Finding.ioc_value == det.ioc_value,
        )
    )
    finding = result.scalar_one_or_none()

    if finding is None:
        finding = Finding(
            customer_id=match.customer_id,
            ioc_type=det.ioc_type,
            ioc_value=det.ioc_value,
            title=_build_title(severity, det.ioc_type, det.ioc_value, match.asset.asset_value),
            cve_id=det.ioc_value if det.ioc_type == "cve_id" else None,
            severity=severity,
            confidence=match.confidence,
            matched_asset=match.asset.asset_value,
            correlation_type=match.correlation_type,
            detection_reason=match.reason,
            source_count=1,
            sources=[det.source],
        )
        session.add(finding)
        await session.flush()
        logger.info("Finding created: customer_id=%s ioc=%s/%s severity=%s",
                    match.customer_id, det.ioc_type, det.ioc_value, severity.value)
    else:
        if finding.sources is None:
            finding.sources = []
        if det.source not in finding.sources:
            finding.sources = [*finding.sources, det.source]
            finding.source_count = (finding.source_count or 0) + 1

        if _SEVERITY_RANK[severity] > _SEVERITY_RANK[finding.severity]:
            finding.severity = severity

        finding.last_seen = det.last_seen or finding.last_seen
        await session.flush()
        logger.info("Finding merged: customer_id=%s ioc=%s/%s source_count=%s",
                    match.customer_id, det.ioc_type, det.ioc_value, finding.source_count)

    det.finding_id = finding.id
    return finding


async def upsert_probable_exposure(
    session: AsyncSession, det: Detection, match: MatchResult,
) -> ProbableExposure:
    """Idempotent on (customer_id, cve_id, product_name, exposure_type)."""
    cve_id = det.ioc_value if det.ioc_type == "cve_id" else None
    product_name = (match.cve_context or {}).get("product")
    exposure_type = "probable_cve" if cve_id else "unknown_version"

    result = await session.execute(
        select(ProbableExposure).where(
            ProbableExposure.customer_id == match.customer_id,
            ProbableExposure.cve_id == cve_id,
            ProbableExposure.product_name == product_name,
            ProbableExposure.exposure_type == exposure_type,
        )
    )
    exposure = result.scalar_one_or_none()

    if exposure is None:
        exposure = ProbableExposure(
            customer_id=match.customer_id,
            exposure_type=exposure_type,
            cve_id=cve_id,
            product_name=product_name,
            source_detail=match.reason,
            confidence=match.confidence,
        )
        session.add(exposure)
        await session.flush()
        logger.info("ProbableExposure created: customer_id=%s cve=%s product=%s",
                    match.customer_id, cve_id, product_name)

    return exposure
