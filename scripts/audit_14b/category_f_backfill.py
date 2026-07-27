"""Category F -- backfill checks (2 checks).

F.1 reuses the existing scripts/backfill_alert_queue.py logic (which
already implements should_dispatch()/dedupe-aware enqueue) instead of
reinventing it with raw SQL against Finding.sources -- that column is
a plain JSON list, not a Postgres ARRAY, so `sources @> ARRAY[...]`
would be invalid SQL against it.

F.2 calls enrichment_v2.aggregator.compute_and_store(ip), which takes
a single IP and returns IpAggregatedScore | None -- there is no batch
variant, so backfill loops over missing IPs one at a time.
"""
from __future__ import annotations

from sqlalchemy import select

from ati_evn.alerts.dedupe import compute_dedupe_key, find_existing_dispatch
from ati_evn.alerts.dispatch_rule import should_dispatch
from ati_evn.config import get_settings
from ati_evn.db.models import AlertQueue, CustomerAsset, Finding, IpAggregatedScore, IpEnrichment
from ati_evn.db.query_utils_test import is_test_finding
from ati_evn.db.session import async_session

_SOURCE_TYPES_TO_BACKFILL = ("exposed_document", "brand_abuse")


async def _find_missing_alertqueue_findings() -> list[Finding]:
    async with async_session() as session:
        candidates = list((await session.execute(
            select(Finding).where(Finding.severity.in_(["HIGH", "CRITICAL"]))
        )).scalars())
        candidates = [
            f for f in candidates
            if not is_test_finding(f)
            and any(s in _SOURCE_TYPES_TO_BACKFILL for s in (f.sources or []))
        ]
        if not candidates:
            return []

        candidate_ids = [f.id for f in candidates]
        queued_ids = {
            row[0] for row in (await session.execute(
                select(AlertQueue.finding_id).where(AlertQueue.finding_id.in_(candidate_ids))
            )).all()
        }
        return [f for f in candidates if f.id not in queued_ids]


async def check_f1(execute: bool = False) -> dict:
    """F.1 -- Backfill missing AlertQueue rows for HIGH/CRITICAL findings
    from exposed_document/brand_abuse sources (mirrors A.4)."""
    missing = await _find_missing_alertqueue_findings()

    if not missing:
        return {"check_id": "F.1", "severity": "PASS"}

    if not execute:
        return {
            "check_id": "F.1",
            "title": f"{len(missing)} finding(s) need AlertQueue backfill",
            "severity": "CRITICAL",
            "description": (
                "Findings from exposed_document/brand_abuse never "
                "dispatched to Bot 1. Re-run with --fix-critical to "
                "insert AlertQueue rows via the same should_dispatch()/"
                "dedupe logic as scripts/backfill_alert_queue.py."
            ),
            "evidence": f"count={len(missing)}, sample_ids={[f.id for f in missing[:5]]}",
            "fix_action": "python -m scripts.audit_14b.run_all --fix-critical",
        }

    settings = get_settings()
    queued = 0
    async with async_session() as session:
        for finding in missing:
            ok, reason = should_dispatch(finding)
            if not ok:
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
                dispatch_reason=f"audit_14b backfill: {reason}",
                dedupe_key=dedupe_key,
                deduped_of_id=existing_id,
            ))
            queued += 1

        await session.commit()

    return {
        "check_id": "F.1", "severity": "INFO",
        "title": f"Backfilled {queued}/{len(missing)} AlertQueue row(s)",
        "description": "Bot 1 will dispatch pending entries on its next poll tick.",
        "evidence": None, "fix_action": None,
    }


async def check_f2(execute: bool = False) -> dict:
    """F.2 -- IPs with per-provider enrichment but no IpAggregatedScore row."""
    async with async_session() as session:
        enriched_ips = {
            row[0] for row in (await session.execute(
                select(IpEnrichment.ip).where(IpEnrichment.error_message.is_(None)).distinct()
            )).all()
        }
        aggregated_ips = {
            row[0] for row in (await session.execute(select(IpAggregatedScore.ip))).all()
        }
    missing_ips = sorted(enriched_ips - aggregated_ips)

    if not missing_ips:
        return {"check_id": "F.2", "severity": "PASS"}

    if not execute:
        return {
            "check_id": "F.2",
            "title": f"{len(missing_ips)} IP(s) need aggregate backfill",
            "severity": "HIGH",
            "description": (
                "IPs have per-provider enrichment rows but no computed "
                "aggregate -- the aggregator should have run on write; "
                "this indicates a trigger gap somewhere in the enrichment path."
            ),
            "evidence": f"count={len(missing_ips)}, samples={missing_ips[:5]}",
            "fix_action": "python -m scripts.audit_14b.run_all --fix-critical",
        }

    from ati_evn.enrichment_v2.aggregator import compute_and_store

    computed = 0
    errors = 0
    for ip in missing_ips:
        try:
            result = await compute_and_store(ip)
            if result is not None:
                computed += 1
        except Exception:
            errors += 1

    return {
        "check_id": "F.2", "severity": "INFO",
        "title": f"Backfilled {computed}/{len(missing_ips)} aggregate row(s) ({errors} error(s))",
        "description": None, "evidence": None, "fix_action": None,
    }
