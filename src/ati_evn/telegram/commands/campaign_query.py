"""/campaign <id> and /list_campaigns commands (read-only)."""
import logging

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Message
from sqlalchemy import func, select

from ati_evn.db.models import Campaign, CampaignFinding, Customer, Finding
from ati_evn.db.query_utils import customer_match_order_by, customer_name_or_code_match
from ati_evn.db.session import async_session
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command
from ati_evn.telegram.formatter.campaign import format_campaign_detail, format_campaign_list

logger = logging.getLogger("ati_evn.telegram.campaign_query")
router = Router()


def _campaign_pagination_keyboard(
    page: int, pages: int, status: str, customer: str | None,
) -> InlineKeyboardMarkup | None:
    if pages <= 1:
        return None
    cust_tok = customer or "-"
    buttons = []
    if page > 1:
        buttons.append(InlineKeyboardButton(
            text="◀ Trang trước", callback_data=f"camp:{page - 1}:{status}:{cust_tok}",
        ))
    if page < pages:
        buttons.append(InlineKeyboardButton(
            text="Trang sau ▶", callback_data=f"camp:{page + 1}:{status}:{cust_tok}",
        ))
    if not buttons:
        return None
    return InlineKeyboardMarkup(inline_keyboard=[buttons])


async def _render_list_campaigns(
    status: str, customer: str | None, page: int, limit: int,
) -> tuple[str, InlineKeyboardMarkup | None] | str:
    offset = (page - 1) * limit

    async with async_session() as session:
        count_stmt = select(func.count(Campaign.id)).where(Campaign.status == status)
        filter_stmt = select(Campaign).where(Campaign.status == status)
        if customer:
            cust_row = await session.execute(
                select(Customer.id).where(customer_name_or_code_match(customer))
                .order_by(customer_match_order_by(customer)).limit(1)
            )
            cust_id = cust_row.scalar_one_or_none()
            if not cust_id:
                return f"Customer '{customer}' không tìm thấy."
            count_stmt = count_stmt.where(Campaign.customer_id == cust_id)
            filter_stmt = filter_stmt.where(Campaign.customer_id == cust_id)

        total = (await session.execute(count_stmt)).scalar() or 0
        filter_stmt = filter_stmt.order_by(
            Campaign.confidence.desc(), Campaign.created_at.desc(), Campaign.id.desc()
        ).limit(limit).offset(offset)
        campaigns = list((await session.execute(filter_stmt)).scalars())

        customer_names = {}
        for c in campaigns:
            if c.customer_id not in customer_names:
                cust = await session.get(Customer, c.customer_id)
                customer_names[c.customer_id] = cust.name if cust else f"#{c.customer_id}"

    text_out = format_campaign_list(
        campaigns, customer_names, total, page, limit, status_filter=status,
    )
    if not campaigns:
        return text_out

    pages = max(1, (total + limit - 1) // limit)
    keyboard = _campaign_pagination_keyboard(page, pages, status, customer)
    return text_out, keyboard


@router.message(Command("campaign"))
@log_command("campaign")
async def cmd_campaign(message: Message):
    args = parse_args(message.text or "", "campaign")
    pos = args.get("_positional", [])
    if not pos:
        await message.answer("Cú pháp: /campaign <id>\nVí dụ: /campaign 12")
        return
    try:
        campaign_id = int(pos[0])
    except ValueError:
        await message.answer(f"ID không hợp lệ: {pos[0]}")
        return
    async with async_session() as session:
        campaign = await session.get(Campaign, campaign_id)
        if not campaign:
            await message.answer(f"Không tìm thấy Campaign #{campaign_id}")
            return
        customer = await session.get(Customer, campaign.customer_id)

        fnd_stmt = select(Finding).join(
            CampaignFinding, Finding.id == CampaignFinding.finding_id,
        ).where(CampaignFinding.campaign_id == campaign.id)
        findings = list((await session.execute(fnd_stmt)).scalars())

        text = format_campaign_detail(campaign, customer, findings)
        await message.answer(text, disable_web_page_preview=True)


@router.message(Command("list_campaigns"))
@log_command("list_campaigns")
async def cmd_list_campaigns(message: Message):
    args = parse_args(message.text or "", "list_campaigns")
    status = (args.get("status") or "candidate").lower()
    customer = args.get("customer")
    limit = int(args.get("limit") or 10)
    page = int(args.get("page") or 1)

    result = await _render_list_campaigns(status, customer, page, limit)
    if isinstance(result, str):
        await message.answer(result)
        return
    text_out, keyboard = result
    await message.answer(text_out, disable_web_page_preview=True, reply_markup=keyboard)


@router.callback_query(lambda c: c.data and c.data.startswith("camp:"))
async def cb_list_campaigns_page(callback: CallbackQuery):
    _, page_str, status, cust_tok = callback.data.split(":", 3)
    page = int(page_str)
    customer = None if cust_tok == "-" else cust_tok

    result = await _render_list_campaigns(status, customer, page, 10)
    if isinstance(result, str):
        await callback.answer(result, show_alert=True)
        return
    text_out, keyboard = result
    await callback.message.edit_text(text_out, reply_markup=keyboard)
    await callback.answer()
