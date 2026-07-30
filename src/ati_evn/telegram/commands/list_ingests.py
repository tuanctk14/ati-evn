"""/list_ingests [--status=pending|confirmed|rejected|expired] [--limit=N] [--page=N]"""
from __future__ import annotations

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Message
from sqlalchemy import func, select

from ati_evn.db.models import IngestionSession
from ati_evn.db.session import async_session
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command
from ati_evn.telegram.formatter.common import fmt_dt, truncate

router = Router()


def _ingests_pagination_keyboard(page: int, pages: int, status: str) -> InlineKeyboardMarkup | None:
    if pages <= 1:
        return None
    buttons = []
    if page > 1:
        buttons.append(InlineKeyboardButton(
            text="◀ Trang trước", callback_data=f"ing:{page - 1}:{status}",
        ))
    if page < pages:
        buttons.append(InlineKeyboardButton(
            text="Trang sau ▶", callback_data=f"ing:{page + 1}:{status}",
        ))
    if not buttons:
        return None
    return InlineKeyboardMarkup(inline_keyboard=[buttons])


async def _render_list_ingests(status: str, page: int, limit: int) -> tuple[str, InlineKeyboardMarkup | None] | str:
    offset = (page - 1) * limit

    async with async_session() as session:
        count_stmt = select(func.count(IngestionSession.id)).where(
            IngestionSession.status == status
        )
        total = (await session.execute(count_stmt)).scalar() or 0

        stmt = (
            select(IngestionSession)
            .where(IngestionSession.status == status)
            .order_by(IngestionSession.created_at.desc(), IngestionSession.id.desc())
            .limit(limit)
            .offset(offset)
        )
        rows = list((await session.execute(stmt)).scalars())

    if not rows:
        return f"Không có ingestion session status={status}."

    pages = max(1, (total + limit - 1) // limit)
    lines = [f"📋 Ingestion sessions — status={status}"]
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
    lines.append(f"\nTrang {page}/{pages} (tổng {total}).")

    keyboard = _ingests_pagination_keyboard(page, pages, status)
    return "\n".join(lines), keyboard


@router.message(Command("list_ingests"))
@log_command("list_ingests")
async def cmd_list_ingests(message: Message):
    args = parse_args(message.text or "", "list_ingests")
    status = (args.get("status") or "pending").lower()
    limit = min(int(args.get("limit") or 10), 20)
    page = int(args.get("page") or 1)

    result = await _render_list_ingests(status, page, limit)
    if isinstance(result, str):
        await message.answer(result)
        return
    text_out, keyboard = result
    await message.answer(text_out, disable_web_page_preview=True, reply_markup=keyboard)


@router.callback_query(lambda c: c.data and c.data.startswith("ing:"))
async def cb_list_ingests_page(callback: CallbackQuery):
    _, page_str, status = callback.data.split(":", 2)
    page = int(page_str)

    result = await _render_list_ingests(status, page, 10)
    if isinstance(result, str):
        await callback.answer(result, show_alert=True)
        return
    text_out, keyboard = result
    await callback.message.edit_text(text_out, reply_markup=keyboard)
    await callback.answer()
