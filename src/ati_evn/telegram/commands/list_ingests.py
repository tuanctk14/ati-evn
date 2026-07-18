"""/list_ingests [--status=pending|confirmed|rejected|expired] [--limit=N] [--page=N]"""
from __future__ import annotations

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message
from sqlalchemy import func, select

from ati_evn.db.models import IngestionSession
from ati_evn.db.session import async_session
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command
from ati_evn.telegram.formatter.common import fmt_dt, truncate

router = Router()


@router.message(Command("list_ingests"))
@log_command("list_ingests")
async def cmd_list_ingests(message: Message):
    args = parse_args(message.text or "", "list_ingests")
    status = (args.get("status") or "pending").lower()
    limit = min(int(args.get("limit") or 10), 20)
    page = int(args.get("page") or 1)
    offset = (page - 1) * limit

    async with async_session() as session:
        count_stmt = select(func.count(IngestionSession.id)).where(
            IngestionSession.status == status
        )
        total = (await session.execute(count_stmt)).scalar() or 0

        stmt = (
            select(IngestionSession)
            .where(IngestionSession.status == status)
            .order_by(IngestionSession.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        rows = list((await session.execute(stmt)).scalars())

    if not rows:
        await message.answer(f"Không có ingestion session status={status}.")
        return

    pages = (total + limit - 1) // limit
    lines = [f"📋 Ingestion sessions — status={status} — trang {page}/{pages} (tổng {total})"]
    for r in rows:
        data = r.extracted_data or {}
        n_iocs = len(data.get("iocs") or [])
        n_cves = len(data.get("cves") or [])
        conf = data.get("confidence", 0)
        src = r.source_url or r.source_filename or "(text)"
        lines.append(
            f"  #{r.id} · {r.source_type} · conf {conf:.2f} · "
            f"{n_iocs}IOC/{n_cves}CVE · {fmt_dt(r.created_at)}\n"
            f"    src: {truncate(src, 70)}"
        )
    if pages > page:
        lines.append(f"\nTrang tiếp: --page={page+1}")
    await message.answer("\n".join(lines), disable_web_page_preview=True)
