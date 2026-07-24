"""One-off backfill: enqueue pre-fix Findings into alert_queue.

Slice 11 (brand_abuse_ingest.py) and slice 10 (document_ingest.py) both
created Finding rows without ever pushing them to alert_queue -- the only
table Bot 1 (telegram/bot_alert.py) polls. This was fixed going forward
in brand_abuse_ingest.py; this script catches up findings created before
the fix, using the exact same should_dispatch()/dedupe rule so backfilled
alerts follow the identical threshold as live ingestion.

Usage: python scripts/backfill_alert_queue.py [--ioc-type=brand_abuse|exposed_document]
"""
from __future__ import annotations

import asyncio
import sys

from sqlalchemy import select

from ati_evn.alerts.dedupe import compute_dedupe_key, find_existing_dispatch
from ati_evn.alerts.dispatch_rule import should_dispatch
from ati_evn.config import get_settings
from ati_evn.db.models import AlertQueue, CustomerAsset, Finding
from ati_evn.db.session import async_session


async def backfill(ioc_type: str) -> dict:
    settings = get_settings()
    stats = {"checked": 0, "already_queued": 0, "below_threshold": 0, "queued": 0}

    async with async_session() as session:
        rows = await session.execute(
            select(Finding).where(Finding.ioc_type == ioc_type).order_by(Finding.id)
        )
        findings = list(rows.scalars())

        for finding in findings:
            stats["checked"] += 1

            existing = await session.execute(
                select(AlertQueue.id).where(AlertQueue.finding_id == finding.id).limit(1)
            )
            if existing.scalar_one_or_none():
                stats["already_queued"] += 1
                continue

            ok, reason = should_dispatch(finding)
            if not ok:
                stats["below_threshold"] += 1
                continue

            asset_id = None
            if finding.matched_asset and finding.matched_asset.startswith("keyword:"):
                keyword = finding.matched_asset.split(":", 1)[1]
                asset_row = await session.execute(
                    select(CustomerAsset.id).where(
                        CustomerAsset.customer_id == finding.customer_id,
                        CustomerAsset.asset_value == keyword,
                    ).limit(1)
                )
                asset_id = asset_row.scalar_one_or_none()

            dedupe_key = compute_dedupe_key(finding.customer_id, finding.ioc_value, asset_id)
            existing_id = await find_existing_dispatch(
                session, dedupe_key, settings.alert_dedupe_window_minutes,
            )
            state = "deduped" if existing_id else "pending"

            session.add(AlertQueue(
                finding_id=finding.id,
                customer_id=finding.customer_id,
                state=state,
                dispatch_reason=f"backfill: {reason}",
                dedupe_key=dedupe_key,
                deduped_of_id=existing_id,
            ))
            stats["queued"] += 1
            print(f"  Finding #{finding.id} ({finding.severity.value}) -> queued, reason={reason}")

        await session.commit()

    return stats


async def main() -> int:
    ioc_type = "brand_abuse"
    for arg in sys.argv[1:]:
        if arg.startswith("--ioc-type="):
            ioc_type = arg.split("=", 1)[1]

    print(f"Backfilling alert_queue for ioc_type={ioc_type}...")
    stats = await backfill(ioc_type)
    print(stats)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
