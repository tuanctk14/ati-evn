"""Category A -- data consistency checks (5 checks).

Schema notes (verified against src/ati_evn/db/models.py, not assumed):
  - Finding.customer_id is NOT NULL -- there is no such thing as an
    "orphan Finding" in this schema. A.1 is reworded to check something
    that can actually occur instead.
  - Finding.status is a SAEnum(FindingStatus) with values
    open/acknowledged/closed/false_positive/expired -- there is no
    'RESOLVED' value.
  - Finding.sources is a plain JSON column (Python list), not a
    Postgres ARRAY -- `sources @> ARRAY[...]` is invalid SQL against
    it. Filtering is done in Python instead.
  - Finding has no deleted_at column (no soft-delete on Finding).
"""
from __future__ import annotations

from pathlib import Path

from sqlalchemy import func, select

from ati_evn.db.models import AlertQueue, Customer, CustomerAsset, Finding, FindingStatus, Report
from ati_evn.db.query_utils_test import is_test_finding
from ati_evn.db.session import async_session


async def check_a1() -> dict:
    """A.1 -- Findings referencing a customer_id that no longer exists.

    Finding.customer_id is NOT NULL with no ondelete clause, so this can
    only happen if a customer row was hard-deleted (not soft-deleted)
    while Findings still referenced it -- schema should prevent it via
    FK, but a prior direct DB edit could still leave stale references if
    the FK was temporarily deferred/disabled.
    """
    async with async_session() as session:
        dangling = (await session.execute(
            select(func.count(Finding.id)).where(
                ~Finding.customer_id.in_(select(Customer.id))
            )
        )).scalar() or 0

    if dangling > 0:
        return {
            "check_id": "A.1",
            "title": f"{dangling} Finding(s) reference a non-existent customer_id",
            "severity": "HIGH",
            "description": (
                "Finding.customer_id has no matching row in customers. "
                "This should be impossible under the FK constraint -- "
                "indicates a prior raw SQL edit bypassed it."
            ),
            "evidence": f"dangling_count={dangling}",
            "fix_action": "Manual investigation required -- not auto-fixable.",
        }
    return {"check_id": "A.1", "severity": "PASS"}


async def check_a2() -> dict:
    """A.2 -- Soft-deleted Customer still has non-terminal Findings or live assets."""
    async with async_session() as session:
        deleted_customers = list((await session.execute(
            select(Customer).where(Customer.deleted_at.is_not(None))
        )).scalars())

        problems = []
        for c in deleted_customers:
            open_findings = (await session.execute(
                select(func.count(Finding.id)).where(
                    Finding.customer_id == c.id,
                    Finding.status.in_([
                        FindingStatus.OPEN, FindingStatus.ACKED,
                    ]),
                )
            )).scalar() or 0
            active_assets = (await session.execute(
                select(func.count(CustomerAsset.id)).where(
                    CustomerAsset.customer_id == c.id,
                    CustomerAsset.deleted_at.is_(None),
                )
            )).scalar() or 0
            if open_findings > 0 or active_assets > 0:
                problems.append((c.id, c.name, open_findings, active_assets))

    if problems:
        return {
            "check_id": "A.2",
            "title": f"{len(problems)} soft-deleted customer(s) with active findings/assets",
            "severity": "MEDIUM",
            "description": (
                "Soft-deleted customers still have OPEN/ACKED findings or "
                "live (non-deleted) assets. This data still surfaces in "
                "global reports/queries that don't filter by customer status."
            ),
            "evidence": "\n".join(
                f"  Customer #{cid} '{name}': {of} open/acked findings, {aa} active assets"
                for cid, name, of, aa in problems
            ),
            "fix_action": (
                "Either cascade-close findings and soft-delete assets when "
                "a customer is soft-deleted, or exclude soft-deleted "
                "customers' children explicitly in report queries. Deferred."
            ),
        }
    return {"check_id": "A.2", "severity": "PASS"}


async def check_a3() -> dict:
    """A.3 -- Report rows with a stale customer_id or missing files on disk."""
    async with async_session() as session:
        orphan_reports = list((await session.execute(
            select(Report.id).where(
                Report.customer_id.is_not(None),
                ~Report.customer_id.in_(select(Customer.id)),
            )
        )).scalars())

        all_reports = list((await session.execute(
            select(Report.id, Report.html_path, Report.pdf_path)
        )).all())

    missing_files = []
    for rid, hpath, ppath in all_reports:
        if hpath and not Path(hpath).exists():
            missing_files.append((rid, "html", hpath))
        if ppath and not Path(ppath).exists():
            missing_files.append((rid, "pdf", ppath))

    issues = []
    if orphan_reports:
        issues.append(f"{len(orphan_reports)} reports reference a non-existent customer_id")
    if missing_files:
        issues.append(f"{len(missing_files)} report files missing from disk")

    if issues:
        return {
            "check_id": "A.3",
            "title": "Report table integrity issues",
            "severity": "MEDIUM",
            "description": "; ".join(issues),
            "evidence": (
                f"Orphan customer_id report IDs: {orphan_reports}\n"
                f"Missing files (report_id, kind, path): {missing_files[:10]}"
            ),
            "fix_action": (
                "Missing files are often relocated/deleted report artifacts "
                "-- decide whether to purge the Report row or note as "
                "expected (e.g. reports/ folder cleaned manually)."
            ),
        }
    return {"check_id": "A.3", "severity": "PASS"}


async def check_a4() -> dict:
    """A.4 -- HIGH/CRITICAL findings from exposed_document/brand_abuse
    sources missing an AlertQueue entry.

    Finding.sources is a plain JSON list column, not a Postgres ARRAY,
    so this is checked in Python after loading candidate rows rather
    than via `sources @> ARRAY[...]` (which is invalid against a plain
    json column and would raise, not silently return 0).
    """
    async with async_session() as session:
        candidates = list((await session.execute(
            select(Finding).where(
                Finding.severity.in_(["HIGH", "CRITICAL"]),
            )
        )).scalars())

        candidates = [
            f for f in candidates
            if not is_test_finding(f)
            and any(s in ("exposed_document", "brand_abuse") for s in (f.sources or []))
        ]
        if not candidates:
            return {"check_id": "A.4", "severity": "PASS"}

        candidate_ids = [f.id for f in candidates]
        queued_ids = {
            row[0] for row in (await session.execute(
                select(AlertQueue.finding_id).where(AlertQueue.finding_id.in_(candidate_ids))
            )).all()
        }
        missing = [f.id for f in candidates if f.id not in queued_ids]

    if missing:
        return {
            "check_id": "A.4",
            "title": f"{len(missing)} HIGH/CRITICAL findings missing AlertQueue entry",
            "severity": "CRITICAL",
            "description": (
                "Findings from exposed_document/brand_abuse sources never "
                "got an AlertQueue row -- Bot 1 never dispatched an alert "
                "for these to the analyst."
            ),
            "evidence": f"missing_count={len(missing)}, sample_ids={missing[:10]}",
            "fix_action": (
                "Run scripts/backfill_alert_queue.py --ioc-type=brand_abuse "
                "and --ioc-type=exposed_document (existing script, reuses "
                "should_dispatch()/dedupe logic -- see category_f_backfill.py)."
            ),
        }
    return {"check_id": "A.4", "severity": "PASS"}


async def check_a5() -> dict:
    """A.5 -- Duplicate findings: same (customer_id, ioc_type, ioc_value)."""
    async with async_session() as session:
        rows = (await session.execute(
            select(
                Finding.customer_id, Finding.ioc_type, Finding.ioc_value,
                func.count().label("cnt"),
            ).group_by(
                Finding.customer_id, Finding.ioc_type, Finding.ioc_value,
            ).having(func.count() > 1).order_by(func.count().desc()).limit(20)
        )).all()

    if rows:
        return {
            "check_id": "A.5",
            "title": f"{len(rows)} duplicate finding group(s)",
            "severity": "MEDIUM",
            "description": (
                "Multiple Finding rows share the same (customer, ioc_type, "
                "ioc_value). May indicate a merge-logic gap in "
                "match/customer_router.py or finding_merger.py."
            ),
            "evidence": "\n".join(
                f"  customer={cid}, {itype}:{(ival or '')[:40]}, count={cnt}"
                for cid, itype, ival, cnt in rows[:10]
            ),
            "fix_action": (
                "Analyst review -- merge or ignore. Consider a partial "
                "unique index after cleanup if this is unintended."
            ),
        }
    return {"check_id": "A.5", "severity": "PASS"}


async def run_all() -> list[dict]:
    results = []
    for check in [check_a1, check_a2, check_a3, check_a4, check_a5]:
        r = await check()
        if r["severity"] != "PASS":
            results.append(r)
    return results
