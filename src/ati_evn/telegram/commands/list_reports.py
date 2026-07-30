"""/list_reports -- list recent reports."""
from __future__ import annotations

import logging

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message
from sqlalchemy import desc, select

from ati_evn.db.models import Customer, Report
from ati_evn.db.query_utils import customer_match_order_by, customer_name_or_code_match
from ati_evn.db.session import async_session
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command

router = Router()
logger = logging.getLogger("ati_evn.telegram.list_reports")


@router.message(Command("list_reports"))
@log_command("list_reports")
async def cmd_list_reports(message: Message):
    args = parse_args(message.text or "", "list_reports")
    limit = int(args.get("limit") or 15)
    report_type = args.get("type")   # global | customer | None (both)
    customer_arg = args.get("customer")

    async with async_session() as session:
        stmt = select(Report).order_by(desc(Report.generated_at)).limit(limit)
        if report_type in ("global", "customer"):
            stmt = stmt.where(Report.report_type == report_type)
        if customer_arg:
            cr = await session.execute(
                select(Customer.id).where(customer_name_or_code_match(customer_arg))
                .order_by(customer_match_order_by(customer_arg)).limit(1)
            )
            cid = cr.scalar_one_or_none()
            if not cid:
                await message.answer(f"⚠️ Customer '{customer_arg}' không tìm thấy.")
                return
            stmt = stmt.where(Report.customer_id == cid)

        reports = list((await session.execute(stmt)).scalars())

        if not reports:
            await message.answer("📭 Không có report nào phù hợp filter.")
            return

        cust_ids = {r.customer_id for r in reports if r.customer_id}
        cust_names = {}
        if cust_ids:
            cust_rows = await session.execute(
                select(Customer.id, Customer.name, Customer.short_code).where(Customer.id.in_(cust_ids))
            )
            for row in cust_rows:
                cust_names[row.id] = row.short_code or row.name

    lines = [f"📊 Recent reports (limit {limit}):", ""]
    for r in reports:
        gen_time = r.generated_at.strftime("%m-%d %H:%M") if r.generated_at else "?"
        window = f"{r.window_from.strftime('%m-%d')} → {r.window_to.strftime('%m-%d')}"
        if r.report_type == "global":
            type_label = "🌐 GLOBAL"
        else:
            cust_label = cust_names.get(r.customer_id, f"#{r.customer_id}")
            type_label = f"👤 {cust_label}"
        size_kb = (r.pdf_size_bytes or r.html_size_bytes or 0) // 1024
        err = " ⚠️" if r.error_message else ""
        lines.append(
            f"#{r.id}  {type_label:20s}  {gen_time}  "
            f"window={window}  {r.findings_total}f  {size_kb}KB{err}"
        )

    lines.append("")
    lines.append("Dùng /download_report <id> để tải file.")
    await message.answer("\n".join(lines))
