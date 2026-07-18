"""/campaign <id> and /list_campaigns commands (read-only)."""
import logging

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message
from sqlalchemy import func, select

from ati_evn.db.models import Campaign, CampaignFinding, Customer, Finding
from ati_evn.db.query_utils import customer_name_or_code_match
from ati_evn.db.session import async_session
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command
from ati_evn.telegram.formatter.campaign import format_campaign_detail, format_campaign_list

logger = logging.getLogger("ati_evn.telegram.campaign_query")
router = Router()


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
    offset = (page - 1) * limit

    async with async_session() as session:
        count_stmt = select(func.count(Campaign.id)).where(
            Campaign.status == status
        )
        filter_stmt = select(Campaign).where(Campaign.status == status)
        if customer:
            cust_row = await session.execute(
                select(Customer.id).where(customer_name_or_code_match(customer))
                .limit(1)
            )
            cust_id = cust_row.scalar_one_or_none()
            if cust_id:
                count_stmt = count_stmt.where(Campaign.customer_id == cust_id)
                filter_stmt = filter_stmt.where(Campaign.customer_id == cust_id)
            else:
                await message.answer(f"Customer '{customer}' không tìm thấy.")
                return

        total = (await session.execute(count_stmt)).scalar() or 0
        filter_stmt = filter_stmt.order_by(
            Campaign.confidence.desc(), Campaign.created_at.desc()
        ).limit(limit).offset(offset)
        campaigns = list((await session.execute(filter_stmt)).scalars())

        customer_names = {}
        for c in campaigns:
            if c.customer_id not in customer_names:
                cust = await session.get(Customer, c.customer_id)
                customer_names[c.customer_id] = cust.name if cust else f"#{c.customer_id}"

        text = format_campaign_list(campaigns, customer_names, total, page, limit,
                                     status_filter=status)
        await message.answer(text, disable_web_page_preview=True)
