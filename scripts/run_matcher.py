"""Batch-match existing Detection rows into customer-scoped Findings.

Usage:
    python scripts/run_matcher.py                 # process NEW only
    python scripts/run_matcher.py --all            # reprocess everything
    python scripts/run_matcher.py --since-hours 6  # window
    python scripts/run_matcher.py --dry-run        # no writes
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from sqlalchemy import text

from ati_evn.db.session import async_session
from ati_evn.match.customer_router import route_detections

logger = logging.getLogger("ati_evn.run_matcher")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all", action="store_true",
                         help="Reprocess all NEW/ROUTED/MERGED detections, not just NEW.")
    parser.add_argument("--since-hours", type=int, default=None,
                         help="Only consider detections created within this window.")
    parser.add_argument("--dry-run", action="store_true",
                         help="Log what would happen; make no DB writes.")
    return parser.parse_args()


async def _print_sql_sanity_block(session) -> None:
    print("\n=== SQL sanity block ===")

    findings_total = (await session.execute(text("SELECT count(*) FROM findings"))).scalar_one()
    print(f"findings total: {findings_total}")

    by_customer = (await session.execute(
        text("SELECT customer_id, count(*) FROM findings GROUP BY customer_id ORDER BY count(*) DESC")
    )).all()
    print(f"findings by customer_id: {dict(by_customer)}")

    by_status = (await session.execute(
        text("SELECT status, count(*) FROM findings GROUP BY status")
    )).all()
    print(f"findings by status: {dict(by_status)}")

    by_correlation = (await session.execute(
        text("SELECT correlation_type, count(*) FROM findings GROUP BY correlation_type")
    )).all()
    print(f"findings by correlation_type: {dict(by_correlation)}")

    probable_total = (await session.execute(
        text("SELECT count(*) FROM probable_exposures")
    )).scalar_one()
    print(f"probable_exposures total: {probable_total}")

    det_by_status = (await session.execute(
        text("SELECT status, count(*) FROM detections GROUP BY status")
    )).all()
    print(f"detections by status: {dict(det_by_status)}")


async def _print_top_findings(session) -> None:
    print("\n=== Top 5 highest-severity Findings ===")
    rows = (await session.execute(text("""
        SELECT c.name, f.ioc_type, f.ioc_value, f.severity, f.correlation_type, f.detection_reason
        FROM findings f
        JOIN customers c ON c.id = f.customer_id
        ORDER BY
            CASE f.severity
                WHEN 'CRITICAL' THEN 4
                WHEN 'HIGH' THEN 3
                WHEN 'MEDIUM' THEN 2
                WHEN 'LOW' THEN 1
                ELSE 0
            END DESC
        LIMIT 5
    """))).all()

    if not rows:
        print("(no findings)")
        return

    for name, ioc_type, ioc_value, severity, correlation_type, reason in rows:
        print(f"  [{severity}] {name} — {ioc_type}:{ioc_value} ({correlation_type})")
        print(f"      reason: {reason}")


async def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )
    args = parse_args()

    async with async_session() as session:
        stats = await route_detections(
            session,
            since_hours=args.since_hours,
            only_new=not args.all,
            dry_run=args.dry_run,
        )

        print("\n=== RouteStats ===")
        print(f"detections_processed        : {stats.detections_processed}")
        print(f"detections_matched          : {stats.detections_matched}")
        print(f"detections_unmatched        : {stats.detections_unmatched}")
        print(f"findings_created            : {stats.findings_created}")
        print(f"findings_merged             : {stats.findings_merged}")
        print(f"findings_auto_fp            : {stats.findings_auto_fp}")
        print(f"probable_exposures_created  : {stats.probable_exposures_created}")
        print(f"per_strategy                : {stats.per_strategy}")

        if args.dry_run:
            print("\n(dry-run: no writes were made)")
            return 0

        await _print_top_findings(session)
        await _print_sql_sanity_block(session)

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
