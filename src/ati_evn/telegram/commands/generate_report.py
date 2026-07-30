"""/generate_report -- generate CyRadar-style report.

Syntax:
  /generate_report                      # default: 7d window, both formats, global
  /generate_report --window=24h
  /generate_report --from=2026-01-15 --to=2026-01-22
  /generate_report --format=html
  /generate_report --format=pdf
  /generate_report --format=both        # default
  /generate_report --customer=NPC       # per-customer scope
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from aiogram import Router
from aiogram.enums import ChatAction
from aiogram.filters import Command
from aiogram.types import FSInputFile, Message
from sqlalchemy import select

from ati_evn.db.models import Customer
from ati_evn.db.query_utils import customer_match_order_by, customer_name_or_code_match
from ati_evn.db.session import async_session
from ati_evn.reports.generator import generate_customer_report, generate_global_report
from ati_evn.telegram.argparse_util import parse_args, parse_iso_date, parse_window
from ati_evn.telegram.audit import log_command, register_command_tool_call

router = Router()
logger = logging.getLogger("ati_evn.telegram.generate_report")


@router.message(Command("generate_report"))
@log_command("generate_report")
async def cmd_generate_report(message: Message):
    args = parse_args(message.text or "", "generate_report")
    window_str = args.get("window")
    from_str = args.get("from")
    to_str = args.get("to")
    customer_arg = args.get("customer")
    format_str = (args.get("format") or "both").lower()

    if format_str == "html":
        formats = ["html"]
    elif format_str == "pdf":
        formats = ["pdf"]
    elif format_str == "both":
        formats = ["html", "pdf"]
    else:
        await message.answer("⚠️ --format phải là html, pdf, hoặc both. Default: both.")
        return

    now = datetime.now(timezone.utc)
    try:
        if from_str or to_str:
            if not (from_str and to_str):
                await message.answer("⚠️ Phải cung cấp cả --from và --to, hoặc dùng --window.")
                return
            from_dt = parse_iso_date(from_str)
            to_dt = parse_iso_date(to_str)
        elif window_str:
            delta = parse_window(window_str)
            to_dt = now
            from_dt = now - delta
        else:
            to_dt = now
            from_dt = now - timedelta(days=7)
    except ValueError as e:
        await message.answer(f"⚠️ Sai format: {e}")
        return

    if from_dt >= to_dt:
        await message.answer("⚠️ --from phải trước --to.")
        return

    customer_id = None
    customer_display = None
    if customer_arg:
        async with async_session() as session:
            r = await session.execute(
                select(Customer.id, Customer.name, Customer.short_code).where(
                    customer_name_or_code_match(customer_arg),
                    Customer.deleted_at.is_(None),
                ).order_by(customer_match_order_by(customer_arg)).limit(1)
            )
            row = r.first()
            if not row:
                await message.answer(
                    f"⚠️ Customer '{customer_arg}' không tìm thấy.\n"
                    "Dùng /list_customers để xem danh sách."
                )
                return
            customer_id = row.id
            customer_display = row.name

    report_type_str = f"customer '{customer_display}'" if customer_id else "global"
    thinking = await message.answer(
        f"📊 Đang generate {report_type_str} report...\n"
        f"  Window: {from_dt.strftime('%Y-%m-%d')} → {to_dt.strftime('%Y-%m-%d')}\n"
        f"  Formats: {', '.join(formats)}\n"
        f"  LLM narrative đang chạy (10-30s)..."
    )
    await message.bot.send_chat_action(message.chat.id, ChatAction.TYPING)

    generated_by = f"analyst:{message.from_user.id}"

    try:
        if customer_id:
            result = await generate_customer_report(
                customer_id, from_dt, to_dt, formats, generated_by=generated_by,
            )
        else:
            result = await generate_global_report(
                from_dt, to_dt, formats, generated_by=generated_by,
            )
    except Exception as e:
        await thinking.delete()
        logger.exception("Report generation failed")
        await message.answer(f"⚠️ Lỗi: {str(e)[:300]}")
        return

    await thinking.delete()

    data = result["data"]
    files = result["files"]

    if customer_id:
        lines = [
            f"✅ Report generated — {customer_display}",
            "",
            f"Report ID: {result['report_id']}",
            f"Window: {from_dt.strftime('%Y-%m-%d')} → {to_dt.strftime('%Y-%m-%d')}",
            f"({data['meta']['window_days']} ngày)",
            "",
            "📊 Coverage:",
            f"  Findings: {data['findings']['total']} "
            f"(CRIT {data['findings']['by_severity'].get('CRITICAL', 0)}, "
            f"HIGH {data['findings']['by_severity'].get('HIGH', 0)})",
            f"  Campaigns: {data['campaigns']['total']}",
            f"  Exposures: {data['exposures']['in_window']} new / "
            f"{data['exposures']['total_active']} active",
            f"  Doc leaks: {data['document_leaks']['in_window']} new",
            f"  Brand abuse: {data['brand_abuse']['in_window']} new",
            f"  Malicious IPs: {data['malicious_ips']['total']} (score ≥ 40)",
        ]
    else:
        lines = [
            "✅ Report generated",
            "",
            f"Report ID: {result['report_id']}",
            f"Window: {from_dt.strftime('%Y-%m-%d')} → {to_dt.strftime('%Y-%m-%d')}",
            f"({data['meta']['window_days']} ngày, {data['meta']['customer_count']} customer)",
            "",
            "📊 Coverage:",
            f"  Findings: {data['findings']['total']} "
            f"(CRIT {data['findings']['by_severity'].get('CRITICAL', 0)}, "
            f"HIGH {data['findings']['by_severity'].get('HIGH', 0)})",
            f"  Campaigns: {data['campaigns']['total']}",
            f"  Exposures: {data['exposures']['in_window']} new / "
            f"{data['exposures']['total_active']} active",
            f"  Doc leaks: {data['document_leaks']['in_window']} new",
            f"  Brand abuse: {data['brand_abuse']['in_window']} new",
            f"  Malicious IPs: {data['malicious_ips']['total']} (score ≥ 40)",
        ]

    if files.get("errors"):
        lines.append("")
        lines.append("⚠️ Warnings:")
        for e in files["errors"]:
            lines.append(f"  - {e}")

    register_command_tool_call(
        message, tool_name="generate_report",
        output_summary=(
            f"Report #{result['report_id']} generated "
            f"({'customer ' + customer_display if customer_id else 'global'}, "
            f"{data['findings']['total']} findings)"
        ),
        entity_ids=[result["report_id"]],
    )
    await message.answer("\n".join(lines))

    if files.get("html_path"):
        try:
            await message.answer_document(
                FSInputFile(files["html_path"]),
                caption=f"HTML ({files['html_size_bytes']:,} bytes)",
            )
        except Exception as e:
            await message.answer(f"⚠️ HTML upload failed: {e}")

    if files.get("pdf_path"):
        try:
            await message.answer_document(
                FSInputFile(files["pdf_path"]),
                caption=f"PDF ({files['pdf_size_bytes']:,} bytes)",
            )
        except Exception as e:
            await message.answer(f"⚠️ PDF upload failed: {e}")
