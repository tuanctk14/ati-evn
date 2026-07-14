"""Read-only query commands. No LLM, no side effects."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message
from sqlalchemy import func, or_, select, text

from ati_evn.db.models import (
    AlertQueue,
    Customer,
    CustomerAsset,
    Detection,
    Finding,
    FindingStatus,
)
from ati_evn.db.query_utils import only_live_asset, only_live_customer
from ati_evn.db.session import async_session
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command
from ati_evn.telegram.formatter.asset import format_asset_detail
from ati_evn.telegram.formatter.customer import format_customer_detail
from ati_evn.telegram.formatter.cve import format_cve_detail
from ati_evn.telegram.formatter.finding import format_finding_detail
from ati_evn.telegram.formatter.ioc import format_ioc_detail
from ati_evn.telegram.formatter.list import format_finding_list
from ati_evn.telegram.formatter.stats import format_stats

router = Router()


# ── /finding <id> ──────────────────────────────────────────────────────────

@router.message(Command("finding"))
@log_command("finding")
async def cmd_finding(message: Message):
    args = parse_args(message.text or "", "finding")
    pos = args.get("_positional", [])
    if not pos:
        await message.answer("Cú pháp: /finding <id>\nVí dụ: /finding 12847")
        return
    try:
        finding_id = int(pos[0])
    except ValueError:
        await message.answer(f"ID không hợp lệ: {pos[0]}")
        return

    async with async_session() as session:
        finding = await session.get(Finding, finding_id)
        if not finding:
            await message.answer(f"Không tìm thấy Finding #{finding_id}")
            return
        customer = await session.get(Customer, finding.customer_id)

        asset = None
        if finding.matched_asset:
            result = await session.execute(
                select(CustomerAsset).where(
                    CustomerAsset.customer_id == finding.customer_id,
                    CustomerAsset.asset_value == finding.matched_asset,
                ).limit(1)
            )
            asset = result.scalar_one_or_none()

        ctx = (finding.metadata_ or {}).get("attack_context") or {}
        text_out = format_finding_detail(finding, customer, asset, ctx)
        await message.answer(text_out, disable_web_page_preview=True)


# ── /cve <cve_id> ──────────────────────────────────────────────────────────

@router.message(Command("cve"))
@log_command("cve")
async def cmd_cve(message: Message):
    args = parse_args(message.text or "", "cve")
    pos = args.get("_positional", [])
    if not pos:
        await message.answer("Cú pháp: /cve <CVE-ID>\nVí dụ: /cve CVE-2024-12345")
        return
    cve_id = pos[0].upper()

    async with async_session() as session:
        det_row = await session.execute(
            select(Detection.raw_text, Detection.metadata_).where(
                Detection.ioc_value == cve_id.lower(),
                Detection.source == "nvd",
            ).limit(1)
        )
        row = det_row.first()
        if not row:
            await message.answer(
                f"CVE {cve_id} không có trong hệ thống.\n"
                f"(Có thể do NVD fetch window ngắn — CVE cũ chưa được lấy.)"
            )
            return
        description = row[0]
        det_meta = row[1] or {}
        cvss = det_meta.get("cvss_score")

        from ati_evn.db.models import CveCweMap, CveProductMap

        cwe_rows = await session.execute(
            select(CveCweMap.cwe_id).where(CveCweMap.cve_id == cve_id)
        )
        cwe_ids = sorted({r[0] for r in cwe_rows})

        prod_rows = await session.execute(
            select(CveProductMap).where(CveProductMap.cve_id == cve_id)
        )
        product_map = list(prod_rows.scalars())

        fnd_row = await session.execute(
            select(Finding).where(
                Finding.ioc_type == "cve_id",
                Finding.ioc_value == cve_id.lower(),
            ).limit(1)
        )
        fnd = fnd_row.scalar_one_or_none()
        attack_ctx = (fnd.metadata_ or {}).get("attack_context") if fnd else {}

        text_out = format_cve_detail(cve_id, description, cvss, cwe_ids, attack_ctx, product_map)
        await message.answer(text_out, disable_web_page_preview=True)


# ── /ioc <value> ─────────────────────────────────────────────────────────────

@router.message(Command("ioc"))
@log_command("ioc")
async def cmd_ioc(message: Message):
    args = parse_args(message.text or "", "ioc")
    pos = args.get("_positional", [])
    if not pos:
        await message.answer("Cú pháp: /ioc <value>\nVí dụ: /ioc 1.2.3.4\n       /ioc example.com")
        return
    ioc_value = pos[0].strip().lower()

    async with async_session() as session:
        det_result = await session.execute(
            select(Detection).where(Detection.ioc_value == ioc_value)
        )
        detections = list(det_result.scalars())
        if not detections:
            await message.answer(f"Không tìm thấy IOC: {ioc_value}")
            return

        ioc_type = detections[0].ioc_type
        finding_ids = {d.finding_id for d in detections if d.finding_id}
        related_findings = []
        if finding_ids:
            fnd_result = await session.execute(
                select(Finding).where(Finding.id.in_(finding_ids))
            )
            related_findings = list(fnd_result.scalars())

        text_out = format_ioc_detail(ioc_type, ioc_value, detections, related_findings)
        await message.answer(text_out, disable_web_page_preview=True)


# ── /asset <id> ────────────────────────────────────────────────────────────

@router.message(Command("asset"))
@log_command("asset")
async def cmd_asset(message: Message):
    args = parse_args(message.text or "", "asset")
    pos = args.get("_positional", [])
    if not pos:
        await message.answer("Cú pháp: /asset <id>\nVí dụ: /asset 42")
        return
    try:
        asset_id = int(pos[0])
    except ValueError:
        await message.answer(f"ID không hợp lệ: {pos[0]}")
        return

    async with async_session() as session:
        asset = await session.get(CustomerAsset, asset_id)
        if not asset:
            await message.answer(f"Không tìm thấy Asset #{asset_id}")
            return
        customer = await session.get(Customer, asset.customer_id)

        finding_count_result = await session.execute(
            select(func.count()).select_from(Finding).where(
                Finding.customer_id == asset.customer_id,
                Finding.matched_asset == asset.asset_value,
                Finding.status == FindingStatus.OPEN,
            )
        )
        finding_count = finding_count_result.scalar_one()

        text_out = format_asset_detail(asset, customer, finding_count)
        await message.answer(text_out, disable_web_page_preview=True)


# ── /customer <id|name> ───────────────────────────────────────────────────

@router.message(Command("customer"))
@log_command("customer")
async def cmd_customer(message: Message):
    args = parse_args(message.text or "", "customer")
    pos = args.get("_positional", [])
    if not pos:
        await message.answer("Cú pháp: /customer <name|id>\nVí dụ: /customer NPC\n       /customer 3")
        return
    query_str = " ".join(pos)

    async with async_session() as session:
        customer = None
        if query_str.isdigit():
            customer = await session.get(Customer, int(query_str))
            if customer is not None and customer.deleted_at is not None:
                customer = None
        if customer is None:
            result = await session.execute(
                select(Customer).where(
                    or_(
                        Customer.name.ilike(f"%{query_str}%"),
                        Customer.short_code.ilike(f"%{query_str}%"),
                    ),
                    only_live_customer(),
                ).limit(1)
            )
            customer = result.scalar_one_or_none()
        if not customer:
            await message.answer(f"Không tìm thấy customer: {query_str}")
            return

        asset_rows = await session.execute(
            select(CustomerAsset.asset_type, func.count()).where(
                CustomerAsset.customer_id == customer.id
            ).group_by(CustomerAsset.asset_type)
        )
        asset_breakdown = {t.value: c for t, c in asset_rows.all()}

        cutoff_30d = datetime.now(timezone.utc) - timedelta(days=30)
        finding_rows = await session.execute(
            select(Finding.severity, func.count()).where(
                Finding.customer_id == customer.id,
                Finding.first_seen >= cutoff_30d,
            ).group_by(Finding.severity)
        )
        finding_counts = {s.value: c for s, c in finding_rows.all()}

        cutoff_24h = datetime.now(timezone.utc) - timedelta(hours=24)
        alert_count_result = await session.execute(
            select(func.count()).select_from(AlertQueue).where(
                AlertQueue.customer_id == customer.id,
                AlertQueue.created_at >= cutoff_24h,
            )
        )
        recent_alerts = alert_count_result.scalar_one()

        top_tech_rows = await session.execute(text("""
            SELECT t->>'id' AS tech_id, count(*) AS n
            FROM findings f, jsonb_array_elements((f.metadata::jsonb->'attack_context'->'techniques')) AS t
            WHERE f.customer_id = :customer_id
              AND f.first_seen >= :cutoff
            GROUP BY t->>'id'
            ORDER BY n DESC
            LIMIT 3
        """), {"customer_id": customer.id, "cutoff": cutoff_30d})
        top_techniques = [(r[0], r[1]) for r in top_tech_rows.all()]

        text_out = format_customer_detail(
            customer, asset_breakdown, finding_counts, recent_alerts, top_techniques,
        )
        await message.answer(text_out, disable_web_page_preview=True)


# ── /stats ─────────────────────────────────────────────────────────────────

@router.message(Command("stats"))
@log_command("stats")
async def cmd_stats(message: Message):
    async with async_session() as session:
        findings_total = (await session.execute(
            select(func.count()).select_from(Finding)
        )).scalar_one()

        status_rows = await session.execute(
            select(Finding.status, func.count()).group_by(Finding.status)
        )
        findings_by_status = {s.value: c for s, c in status_rows.all()}

        sev_rows = await session.execute(
            select(Finding.severity, func.count()).group_by(Finding.severity)
        )
        findings_by_severity = {s.value: c for s, c in sev_rows.all()}

        detections_total = (await session.execute(
            select(func.count()).select_from(Detection)
        )).scalar_one()

        source_rows = await session.execute(
            select(Detection.source, func.count()).group_by(Detection.source)
            .order_by(func.count().desc()).limit(5)
        )
        detections_by_source = [(s, c) for s, c in source_rows.all()]

        cutoff_24h = datetime.now(timezone.utc) - timedelta(hours=24)
        dispatch_rows = await session.execute(
            select(AlertQueue.state, func.count()).where(
                AlertQueue.created_at >= cutoff_24h,
            ).group_by(AlertQueue.state)
        )
        dispatch_stats = dict(dispatch_rows.all())

        top_customer_rows = await session.execute(
            select(Customer.name, func.count()).join(
                Finding, Finding.customer_id == Customer.id,
            ).where(Finding.status == FindingStatus.OPEN, only_live_customer())
            .group_by(Customer.name).order_by(func.count().desc()).limit(5)
        )
        top_customers = [(n, c) for n, c in top_customer_rows.all()]

        cutoff_7d = datetime.now(timezone.utc) - timedelta(days=7)
        top_tech_rows = await session.execute(text("""
            SELECT t->>'id' AS tech_id, count(*) AS n
            FROM findings f, jsonb_array_elements((f.metadata::jsonb->'attack_context'->'techniques')) AS t
            WHERE f.first_seen >= :cutoff
            GROUP BY t->>'id'
            ORDER BY n DESC
            LIMIT 5
        """), {"cutoff": cutoff_7d})
        top_techniques = [(r[0], r[1]) for r in top_tech_rows.all()]

        top_vendor_rows = await session.execute(text("""
            SELECT ca.vendor, count(DISTINCT f.id) AS n
            FROM findings f
            JOIN customer_assets ca ON ca.asset_value = f.matched_asset
                AND ca.customer_id = f.customer_id
            WHERE ca.vendor IS NOT NULL
            GROUP BY ca.vendor
            ORDER BY n DESC
            LIMIT 5
        """))
        top_vendors = [(r[0], r[1]) for r in top_vendor_rows.all()]

        latest_ingest_result = await session.execute(
            select(func.max(Detection.created_at))
        )
        latest_ingest = latest_ingest_result.scalar_one()
        from ati_evn.telegram.formatter.common import fmt_dt
        latest_ingest_str = f"{fmt_dt(latest_ingest)} ICT" if latest_ingest else None

        counters = {
            "findings_total": findings_total,
            "findings_by_status": findings_by_status,
            "findings_by_severity": findings_by_severity,
            "detections_total": detections_total,
            "detections_by_source": detections_by_source,
            "top_vendors": top_vendors,
            "latest_ingest": latest_ingest_str,
        }

        text_out = format_stats(counters, top_customers, top_techniques, dispatch_stats)
        await message.answer(text_out, disable_web_page_preview=True)


# ── /list_open [--severity=] [--customer=] [--limit=] [--page=] ────────────

@router.message(Command("list_open"))
@log_command("list_open")
async def cmd_list_open(message: Message):
    args = parse_args(message.text or "", "list_open")
    severity = args.get("severity")
    customer_filter = args.get("customer")
    try:
        per_page = int(args.get("limit", 10))
    except ValueError:
        per_page = 10
    try:
        page = max(1, int(args.get("page", 1)))
    except ValueError:
        page = 1

    async with async_session() as session:
        stmt = select(Finding, Customer.name).join(
            Customer, Customer.id == Finding.customer_id,
        ).where(Finding.status == FindingStatus.OPEN, only_live_customer())

        if severity:
            stmt = stmt.where(Finding.severity == severity.upper())
        if customer_filter:
            stmt = stmt.where(Customer.name.ilike(f"%{customer_filter}%"))

        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = (await session.execute(count_stmt)).scalar_one()

        stmt = stmt.order_by(
            Finding.severity.desc(), Finding.first_seen.desc(),
        ).limit(per_page).offset((page - 1) * per_page)

        rows = (await session.execute(stmt)).all()

        text_out = format_finding_list(rows, total, page, per_page)
        await message.answer(text_out, disable_web_page_preview=True)


# ── /list_alerts [--recent=] [--customer=] [--state=] ───────────────────────

@router.message(Command("list_alerts"))
@log_command("list_alerts")
async def cmd_list_alerts(message: Message):
    args = parse_args(message.text or "", "list_alerts")
    recent = args.get("recent", "24h")
    customer_filter = args.get("customer")
    state_filter = args.get("state")

    unit_map = {"h": "hours", "m": "minutes", "d": "days"}
    try:
        num = int(recent[:-1])
        unit = unit_map.get(recent[-1], "hours")
        cutoff = datetime.now(timezone.utc) - timedelta(**{unit: num})
    except (ValueError, IndexError):
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

    async with async_session() as session:
        stmt = select(AlertQueue, Customer.name).join(
            Customer, Customer.id == AlertQueue.customer_id,
        ).where(AlertQueue.created_at >= cutoff)

        if customer_filter:
            stmt = stmt.where(Customer.name.ilike(f"%{customer_filter}%"))
        if state_filter:
            stmt = stmt.where(AlertQueue.state == state_filter)

        stmt = stmt.order_by(AlertQueue.created_at.desc()).limit(20)
        rows = (await session.execute(stmt)).all()

        if not rows:
            await message.answer(f"Không có alert nào trong {recent} qua.")
            return

        from ati_evn.telegram.formatter.common import fmt_dt

        lines = [f"📨 Alert list — {len(rows)} kết quả (gần đây)", ""]
        for alert, customer_name in rows:
            lines.append(
                f"#{alert.id} finding=#{alert.finding_id} state={alert.state} "
                f"{customer_name} — {fmt_dt(alert.dispatched_at or alert.created_at)}"
            )
        await message.answer("\n".join(lines), disable_web_page_preview=True)
