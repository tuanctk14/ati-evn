"""/list_indicators [--type=T] [--customer=X] [--severity=S] [--status=active] [--limit=N] [--page=N]"""
from __future__ import annotations

import logging
import math

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Message
from sqlalchemy import desc, func, select

from ati_evn.db.models import Customer, ThreatIndicator
from ati_evn.db.query_utils import customer_match_order_by, customer_name_or_code_match, ti_default_status_filter
from ati_evn.db.session import async_session
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command
from ati_evn.telegram.formatter.common import fmt_dt

router = Router()
logger = logging.getLogger("ati_evn.telegram.list_indicators")

BADGE = {
    "brand_abuse": "🎭", "exposed_document": "📄",
    "exposure": "📡", "ipv4": "🔎", "ipv6": "🔎",
    "domain": "🔎", "url": "🔎",
    "sha256": "🔎", "sha1": "🔎", "md5": "🔎",
}


def _pagination_keyboard(
    page: int, total_pages: int,
    indicator_type: str | None, customer: str | None, severity: str | None, status: str | None,
) -> InlineKeyboardMarkup | None:
    """Prev/Next buttons. callback_data format:
    'li:{page}:{type}:{customer}:{severity}:{status}' -- '-' stands in
    for an unset filter since callback_data can't contain empty segments
    cleanly with split(':').
    """
    if total_pages <= 1:
        return None

    tok = lambda v: v or "-"
    parts = f"{tok(indicator_type)}:{tok(customer)}:{tok(severity)}:{tok(status)}"
    buttons = []
    if page > 1:
        buttons.append(InlineKeyboardButton(
            text="◀ Trang trước", callback_data=f"li:{page - 1}:{parts}",
        ))
    if page < total_pages:
        buttons.append(InlineKeyboardButton(
            text="Trang sau ▶", callback_data=f"li:{page + 1}:{parts}",
        ))
    if not buttons:
        return None
    return InlineKeyboardMarkup(inline_keyboard=[buttons])


async def _render_list_indicators(
    indicator_type: str | None, customer_arg: str | None, severity: str | None,
    status_arg: str | None, page: int, per_page: int,
) -> tuple[str, InlineKeyboardMarkup | None] | str:
    """Shared query+render for both the /list_indicators command and its
    Prev/Next callback buttons. Returns an error string on customer
    resolve failure, else (text, keyboard)."""
    async with async_session() as session:
        base_stmt = select(ThreatIndicator)

        if status_arg:
            base_stmt = base_stmt.where(ThreatIndicator.status == status_arg)
        else:
            base_stmt = base_stmt.where(ti_default_status_filter())

        if indicator_type:
            base_stmt = base_stmt.where(ThreatIndicator.indicator_type == indicator_type)
        if severity:
            base_stmt = base_stmt.where(ThreatIndicator.severity == severity.upper())

        if customer_arg:
            cr = await session.execute(
                select(Customer.id).where(customer_name_or_code_match(customer_arg))
                .order_by(customer_match_order_by(customer_arg)).limit(1)
            )
            cid = cr.scalar_one_or_none()
            if not cid:
                return f"⚠️ Customer '{customer_arg}' không tìm thấy."
            base_stmt = base_stmt.where(ThreatIndicator.customer_id == cid)

        count_stmt = select(func.count()).select_from(base_stmt.subquery())
        total = (await session.execute(count_stmt)).scalar_one()

        stmt = base_stmt.order_by(
            desc(ThreatIndicator.first_seen), desc(ThreatIndicator.id)
        ).limit(per_page).offset((page - 1) * per_page)
        rows = list((await session.execute(stmt)).scalars())

        customer_names: dict[int, str] = {}
        for ti in rows:
            if ti.customer_id and ti.customer_id not in customer_names:
                c = await session.get(Customer, ti.customer_id)
                customer_names[ti.customer_id] = (c.short_code or c.name) if c else f"#{ti.customer_id}"

    total_pages = max(1, math.ceil(total / per_page))
    header = f"📋 Threat Indicators (status={status_arg}):" if status_arg else "📋 Threat Indicators:"
    lines = [header, ""]

    if not rows:
        lines.append("(không có kết quả)")
    for ti in rows:
        badge = BADGE.get(ti.indicator_type, "⚠️")
        sev = ti.severity.value if hasattr(ti.severity, "value") else str(ti.severity)
        cust = customer_names.get(ti.customer_id, f"#{ti.customer_id}")
        first_seen = fmt_dt(ti.first_seen) if ti.first_seen else "?"
        ack_flag = " ✓ACK" if ti.acknowledged_at else ""
        lines.append(
            f"{badge} #{ti.id}  [{sev}]  {cust}  "
            f"{ti.indicator_type}  {ti.title[:50]}  "
            f"{first_seen}{ack_flag}"
        )

    lines.append("")
    lines.append("Dùng /indicator <id> để xem chi tiết.")
    lines.append(f"Trang {page}/{total_pages} (tổng {total}).")
    keyboard = _pagination_keyboard(page, total_pages, indicator_type, customer_arg, severity, status_arg)
    return "\n".join(lines), keyboard


@router.message(Command("list_indicators"))
@log_command("list_indicators")
async def cmd_list_indicators(message: Message):
    args = parse_args(message.text or "", "list_indicators")
    indicator_type = args.get("type")
    customer_arg = args.get("customer")
    severity = args.get("severity")
    status_arg = (args.get("status") or "").lower() or None
    try:
        limit = min(max(int(args.get("limit") or 20), 1), 50)
    except ValueError:
        limit = 20
    try:
        page = max(1, int(args.get("page") or 1))
    except ValueError:
        page = 1

    result = await _render_list_indicators(
        indicator_type, customer_arg, severity, status_arg, page, limit,
    )
    if isinstance(result, str):
        await message.answer(result)
        return
    text_out, keyboard = result
    await message.answer(text_out, disable_web_page_preview=True, reply_markup=keyboard)


@router.callback_query(lambda c: c.data and c.data.startswith("li:"))
async def cb_list_indicators_page(callback: CallbackQuery):
    _, page_str, type_tok, cust_tok, sev_tok, status_tok = callback.data.split(":", 5)
    page = int(page_str)
    indicator_type = None if type_tok == "-" else type_tok
    customer_arg = None if cust_tok == "-" else cust_tok
    severity = None if sev_tok == "-" else sev_tok
    status_arg = None if status_tok == "-" else status_tok

    result = await _render_list_indicators(
        indicator_type, customer_arg, severity, status_arg, page, 20,
    )
    if isinstance(result, str):
        await callback.answer(result, show_alert=True)
        return
    text_out, keyboard = result
    await callback.message.edit_text(text_out, reply_markup=keyboard)
    await callback.answer()
