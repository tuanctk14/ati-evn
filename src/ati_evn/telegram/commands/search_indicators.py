"""/search_indicators --keyword=X [--source=Y] [--since_days=N] [--limit=N] [--page=N]"""
from __future__ import annotations

import hashlib
import logging
import math
from datetime import datetime, timedelta, timezone

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Message
from sqlalchemy import desc, func, select

from ati_evn.db.models import Customer, ThreatIndicator
from ati_evn.db.query_utils import customer_match_order_by, customer_name_or_code_match
from ati_evn.db.session import async_session
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command
from ati_evn.telegram.formatter.common import fmt_dt

router = Router()
logger = logging.getLogger("ati_evn.telegram.search_indicators")

BADGE = {
    "brand_abuse": "🎭", "exposed_document": "📄",
    "exposure": "📡", "ipv4": "🔎", "ipv6": "🔎",
    "domain": "🔎", "url": "🔎",
    "sha256": "🔎", "sha1": "🔎", "md5": "🔎",
}

# callback_data has a 64-byte limit and keyword/customer can be
# arbitrary-length free text, so the filter combo is cached server-side
# under a short hash key rather than serialized into callback_data
# directly (contrast with /list_indicators, whose filters are all
# short enum-like tokens that fit inline).
_SEARCH_CACHE: dict[str, dict] = {}
_SEARCH_CACHE_MAX = 200


def _cache_search_params(params: dict) -> str:
    key = hashlib.sha256(repr(sorted(params.items())).encode()).hexdigest()[:16]
    if len(_SEARCH_CACHE) >= _SEARCH_CACHE_MAX:
        _SEARCH_CACHE.pop(next(iter(_SEARCH_CACHE)))
    _SEARCH_CACHE[key] = params
    return key


def _search_pagination_keyboard(page: int, total_pages: int, cache_key: str) -> InlineKeyboardMarkup | None:
    if total_pages <= 1:
        return None
    buttons = []
    if page > 1:
        buttons.append(InlineKeyboardButton(
            text="◀ Trang trước", callback_data=f"si:{page - 1}:{cache_key}",
        ))
    if page < total_pages:
        buttons.append(InlineKeyboardButton(
            text="Trang sau ▶", callback_data=f"si:{page + 1}:{cache_key}",
        ))
    if not buttons:
        return None
    return InlineKeyboardMarkup(inline_keyboard=[buttons])


async def _render_search_indicators(
    keyword: str | None, source: str | None, customer_arg: str | None,
    indicator_type: str | None, since_days: int, page: int, per_page: int,
) -> tuple[str, InlineKeyboardMarkup | None] | str:
    cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)

    async with async_session() as session:
        base_stmt = select(ThreatIndicator).where(ThreatIndicator.first_seen >= cutoff)

        if indicator_type:
            base_stmt = base_stmt.where(ThreatIndicator.indicator_type == indicator_type)
        if source:
            base_stmt = base_stmt.where(ThreatIndicator.source == source)
        if keyword:
            pattern = f"%{keyword}%"
            base_stmt = base_stmt.where(
                (ThreatIndicator.title.ilike(pattern))
                | (ThreatIndicator.indicator_value.ilike(pattern))
            )
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
    lines = [f"🔍 Search Indicators (since_days={since_days}):", ""]

    if not rows:
        lines.append("(không có kết quả)")
    for ti in rows:
        badge = BADGE.get(ti.indicator_type, "⚠️")
        sev = ti.severity.value if hasattr(ti.severity, "value") else str(ti.severity)
        cust = customer_names.get(ti.customer_id, f"#{ti.customer_id}")
        first_seen = fmt_dt(ti.first_seen) if ti.first_seen else "?"
        lines.append(
            f"{badge} #{ti.id}  [{sev}]  {cust}  {ti.indicator_type}  "
            f"{ti.title[:50]}  {first_seen}"
        )

    lines.append("")
    lines.append("Dùng /indicator <id> để xem chi tiết.")
    lines.append(f"Trang {page}/{total_pages} (tổng {total}).")

    cache_key = _cache_search_params({
        "keyword": keyword, "source": source, "customer": customer_arg,
        "type": indicator_type, "since_days": since_days, "limit": per_page,
    })
    keyboard = _search_pagination_keyboard(page, total_pages, cache_key)
    return "\n".join(lines), keyboard


@router.message(Command("search_indicators"))
@log_command("search_indicators")
async def cmd_search_indicators(message: Message):
    args = parse_args(message.text or "", "search_indicators")
    keyword = args.get("keyword")
    source = args.get("source")
    customer_arg = args.get("customer")
    indicator_type = args.get("type")
    try:
        since_days = int(args.get("since_days") or 30)
    except ValueError:
        since_days = 30
    try:
        limit = min(max(int(args.get("limit") or 20), 1), 50)
    except ValueError:
        limit = 20
    try:
        page = max(1, int(args.get("page") or 1))
    except ValueError:
        page = 1

    result = await _render_search_indicators(
        keyword, source, customer_arg, indicator_type, since_days, page, limit,
    )
    if isinstance(result, str):
        await message.answer(result)
        return
    text_out, keyboard = result
    await message.answer(text_out, disable_web_page_preview=True, reply_markup=keyboard)


@router.callback_query(lambda c: c.data and c.data.startswith("si:"))
async def cb_search_indicators_page(callback: CallbackQuery):
    _, page_str, cache_key = callback.data.split(":", 2)
    page = int(page_str)
    params = _SEARCH_CACHE.get(cache_key)
    if params is None:
        await callback.answer("⚠️ Phiên tìm kiếm đã hết hạn, vui lòng chạy lại /search_indicators.", show_alert=True)
        return

    result = await _render_search_indicators(
        params["keyword"], params["source"], params["customer"], params["type"],
        params["since_days"], page, params["limit"],
    )
    if isinstance(result, str):
        await callback.answer(result, show_alert=True)
        return
    text_out, keyboard = result
    await callback.message.edit_text(text_out, reply_markup=keyboard)
    await callback.answer()
