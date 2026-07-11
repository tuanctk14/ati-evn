"""Orchestrator: iterate Detections × 5 match strategies, produce Findings.

Batch-oriented — this is a manual runner (scripts/run_matcher.py), not a
real-time hook (that lands in slice 5). Commits in chunks of ~200 so a crash
mid-run doesn't lose everything already processed.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ati_evn.db.models import Detection, DetectionStatus, FpMemory
from ati_evn.match.asset_index import AssetIndex
from ati_evn.match.finding_merger import upsert_finding, upsert_probable_exposure
from ati_evn.match.fp_check import is_false_positive
from ati_evn.match.severity_apply import compute_finding_severity
from ati_evn.match.strategies import ALL_STRATEGIES, MatchResult

logger = logging.getLogger("ati_evn.match.customer_router")

COMMIT_BATCH_SIZE = 200


@dataclass
class RouteStats:
    detections_processed: int = 0
    detections_matched: int = 0
    detections_unmatched: int = 0
    findings_created: int = 0
    findings_merged: int = 0
    findings_auto_fp: int = 0
    probable_exposures_created: int = 0
    per_strategy: dict[str, int] = field(default_factory=dict)

    def bump_strategy(self, correlation_type: str) -> None:
        self.per_strategy[correlation_type] = self.per_strategy.get(correlation_type, 0) + 1


def _run_all_strategies(det: Detection, idx: AssetIndex) -> list[MatchResult]:
    results: list[MatchResult] = []
    for strategy in ALL_STRATEGIES:
        try:
            results.extend(strategy(det, idx))
        except Exception:
            logger.exception(
                "Strategy %s blew up on detection id=%s ioc=%s/%s — skipping strategy for this detection",
                strategy.__name__, det.id, det.ioc_type, det.ioc_value,
            )
    return results


def _best_per_customer(matches: list[MatchResult]) -> dict[int, MatchResult]:
    best: dict[int, MatchResult] = {}
    for m in matches:
        current = best.get(m.customer_id)
        if current is None or m.confidence > current.confidence:
            best[m.customer_id] = m
    return best


async def _select_detections(
    session: AsyncSession, since_hours: int | None, only_new: bool,
    only_status: DetectionStatus | None,
) -> list[Detection]:
    stmt = select(Detection)

    if only_status is not None:
        stmt = stmt.where(Detection.status == only_status)
    elif only_new:
        stmt = stmt.where(Detection.status == DetectionStatus.NEW, Detection.finding_id.is_(None))
    else:
        stmt = stmt.where(
            Detection.status.in_([DetectionStatus.NEW, DetectionStatus.ROUTED, DetectionStatus.MERGED])
        )

    if since_hours is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=since_hours)
        stmt = stmt.where(Detection.created_at >= cutoff)

    result = await session.execute(stmt)
    return list(result.scalars().all())


async def route_detections(
    session: AsyncSession,
    since_hours: int | None = None,
    only_new: bool = True,
    dry_run: bool = False,
    only_status: DetectionStatus | None = None,
) -> RouteStats:
    """Batch-match Detections against the current AssetIndex.

    only_status, when set, overrides only_new and selects Detections with
    exactly that status (e.g. DetectionStatus.UNMATCHED for a rescan pass
    after a new asset was added — those rows were correctly unmatched
    against the OLD asset set and deserve a fresh look against the new one).
    """
    stats = RouteStats()
    idx = await AssetIndex.build(session)
    detections = await _select_detections(session, since_hours, only_new, only_status)

    logger.info(
        "route_detections: %d candidate detections (only_new=%s, only_status=%s, since_hours=%s, dry_run=%s)",
        len(detections), only_new, only_status, since_hours, dry_run,
    )

    for i, det in enumerate(detections, start=1):
        stats.detections_processed += 1

        try:
            matches = _run_all_strategies(det, idx)
        except Exception:
            logger.exception("Unhandled error processing detection id=%s — skipping", det.id)
            continue

        if not matches:
            stats.detections_unmatched += 1
            if not dry_run:
                det.status = DetectionStatus.UNMATCHED
            continue

        stats.detections_matched += 1
        best_by_customer = _best_per_customer(matches)

        for customer_id, match in best_by_customer.items():
            stats.bump_strategy(match.correlation_type)

            if dry_run:
                continue

            try:
                is_fp, fp_row_id = await is_false_positive(
                    session, customer_id, det.ioc_type, det.ioc_value,
                    asset_id=match.asset.id if match.asset is not None else None,
                )
                if is_fp:
                    stats.findings_auto_fp += 1
                    if fp_row_id is not None:
                        fp_row = await session.get(FpMemory, fp_row_id)
                        if fp_row is not None:
                            fp_row.hit_count = (fp_row.hit_count or 0) + 1
                            fp_row.last_hit_at = datetime.now(timezone.utc)
                    continue

                severity, _breakdown = compute_finding_severity(det, match)

                if match.is_probable:
                    await upsert_probable_exposure(session, det, match)
                    stats.probable_exposures_created += 1
                else:
                    finding = await upsert_finding(session, det, match, severity)
                    if finding.source_count == 1:
                        stats.findings_created += 1
                    else:
                        stats.findings_merged += 1

            except Exception:
                logger.exception(
                    "Error routing detection id=%s to customer_id=%s — skipping this match",
                    det.id, customer_id,
                )
                continue

        if not dry_run:
            det.status = DetectionStatus.ROUTED
            top_match = max(best_by_customer.values(), key=lambda m: m.confidence)
            det.customer_id = top_match.customer_id
            det.correlation_type = top_match.correlation_type
            det.matched_asset = top_match.asset.asset_value

        if not dry_run and i % COMMIT_BATCH_SIZE == 0:
            await session.commit()
            logger.info("Committed batch at %d/%d detections", i, len(detections))

    if not dry_run:
        await session.commit()

    logger.info(
        "route_detections done: processed=%d matched=%d unmatched=%d "
        "findings_created=%d findings_merged=%d auto_fp=%d probable_exposures=%d",
        stats.detections_processed, stats.detections_matched, stats.detections_unmatched,
        stats.findings_created, stats.findings_merged, stats.findings_auto_fp,
        stats.probable_exposures_created,
    )
    return stats
