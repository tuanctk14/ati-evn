"""Manual test: pick a real Finding, insert an alert_queue row, let the
dispatcher pick it up.

Usage:
  python scripts/inject_test_alert.py --finding-id <id>
"""
from __future__ import annotations

import argparse
import asyncio
import sys

from sqlalchemy import select

from ati_evn.alerts.dedupe import compute_dedupe_key, find_existing_dispatch
from ati_evn.config import get_settings
from ati_evn.db.models import AlertQueue, CustomerAsset, Finding
from ati_evn.db.session import async_session


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--finding-id", type=int, required=True)
    args = ap.parse_args()

    async with async_session() as session:
        finding = await session.get(Finding, args.finding_id)
        if not finding:
            print(f"Finding {args.finding_id} not found")
            return 1

        # Resolve the same asset_id the router hook would have used, so the
        # dedupe_key computed here matches what a real matcher-driven alert
        # for this finding would produce — otherwise this tool can't be used
        # to test dedupe at all (it would always mint a fresh, non-colliding
        # key by construction).
        asset_id = None
        if finding.matched_asset:
            result = await session.execute(
                select(CustomerAsset.id).where(
                    CustomerAsset.customer_id == finding.customer_id,
                    CustomerAsset.asset_value == finding.matched_asset,
                ).limit(1)
            )
            asset_id = result.scalar_one_or_none()

        key = compute_dedupe_key(finding.customer_id, finding.ioc_value, asset_id)

        # Same dedupe check the router hook performs — otherwise this tool
        # would always insert state=pending regardless of prior dispatches,
        # making it useless for testing dedupe behavior.
        settings = get_settings()
        existing_id = await find_existing_dispatch(
            session, key, settings.alert_dedupe_window_minutes,
        )
        state = "deduped" if existing_id else "pending"

        aq = AlertQueue(
            finding_id=finding.id,
            customer_id=finding.customer_id,
            state=state,
            dispatch_reason="manual_test",
            dedupe_key=key,
            deduped_of_id=existing_id,
        )
        session.add(aq)
        await session.commit()
        if state == "deduped":
            print(f"Queued alert #{aq.id} for finding {finding.id} — "
                  f"DEDUPED against existing alert #{existing_id}.")
        else:
            print(f"Queued alert #{aq.id} for finding {finding.id}. "
                  f"Bot 1 should dispatch within 5s.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
