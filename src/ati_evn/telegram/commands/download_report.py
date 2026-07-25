"""/download_report <id> [--format=html|pdf|both]"""
from __future__ import annotations

import logging
from pathlib import Path

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import FSInputFile, Message

from ati_evn.db.models import Report
from ati_evn.db.session import async_session
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command

router = Router()
logger = logging.getLogger("ati_evn.telegram.download_report")


@router.message(Command("download_report"))
@log_command("download_report")
async def cmd_download_report(message: Message):
    args = parse_args(message.text or "", "download_report")
    pos = args.get("_positional", [])
    format_str = (args.get("format") or "both").lower()
    if not pos:
        await message.answer("Cú pháp: /download_report <id> [--format=html|pdf|both]")
        return

    try:
        report_id = int(pos[0])
    except ValueError:
        await message.answer("⚠️ ID phải là số nguyên.")
        return

    async with async_session() as session:
        report = await session.get(Report, report_id)
        if not report:
            await message.answer(f"⚠️ Report #{report_id} không tồn tại.")
            return

    if format_str == "html":
        formats = ["html"]
    elif format_str == "pdf":
        formats = ["pdf"]
    else:
        formats = ["html", "pdf"]

    sent = 0
    if "html" in formats and report.html_path:
        if Path(report.html_path).exists():
            try:
                await message.answer_document(
                    FSInputFile(report.html_path),
                    caption=f"Report #{report.id} — HTML ({report.html_size_bytes:,} bytes)",
                )
                sent += 1
            except Exception as e:
                await message.answer(f"⚠️ HTML upload failed: {e}")
        else:
            await message.answer(f"⚠️ HTML file không tồn tại: {report.html_path}")

    if "pdf" in formats and report.pdf_path:
        if Path(report.pdf_path).exists():
            try:
                await message.answer_document(
                    FSInputFile(report.pdf_path),
                    caption=f"Report #{report.id} — PDF ({report.pdf_size_bytes:,} bytes)",
                )
                sent += 1
            except Exception as e:
                await message.answer(f"⚠️ PDF upload failed: {e}")
        else:
            await message.answer(f"⚠️ PDF file không tồn tại: {report.pdf_path}")

    if sent == 0:
        await message.answer(f"⚠️ Report #{report_id} không có file khả dụng (format={format_str}).")
