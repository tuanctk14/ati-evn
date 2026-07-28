"""/scan_urlscan --keyword=X [--domain=Y] [--max=50] — on-demand brand abuse scan.
   /scan_urlscan --customer=X [--max=50] — resolve keyword/domain from customer record.
"""
from __future__ import annotations

import logging

from aiogram import Router
from aiogram.enums import ChatAction
from aiogram.filters import Command
from aiogram.types import Message
from sqlalchemy import select

from ati_evn.config import get_settings
from ati_evn.db.models import Customer
from ati_evn.db.query_utils import customer_name_or_code_match, only_live_customer
from ati_evn.db.session import async_session
from ati_evn.external.brand_abuse_ingest import ingest_brand_abuse
from ati_evn.external.urlscan_client import UrlscanAPIError, UrlscanConfigError, search_brand
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command

logger = logging.getLogger("ati_evn.telegram.scan_urlscan")
router = Router()


@router.message(Command("scan_urlscan"))
@log_command("scan_urlscan")
async def cmd_scan_urlscan(message: Message):
    args = parse_args(message.text or "", "scan_urlscan")
    keyword = args.get("keyword")
    domain = args.get("domain")
    customer_query = args.get("customer")
    settings = get_settings()
    max_results = int(args.get("max") or settings.urlscan_max_results_per_query)

    if customer_query and not keyword:
        async with async_session() as session:
            row = await session.execute(
                select(Customer).where(
                    customer_name_or_code_match(customer_query), only_live_customer(),
                ).limit(1)
            )
            customer = row.scalar_one_or_none()
        if not customer:
            await message.answer(f"Customer '{customer_query}' không tồn tại.")
            return
        keyword = customer.name
        domain = domain or customer.primary_domain

    if not keyword:
        await message.answer(
            "Cú pháp: /scan_urlscan --keyword=X [--domain=Y] [--max=50]\n"
            "       /scan_urlscan --customer=X [--max=50]\n"
            "Ví dụ: /scan_urlscan --keyword=\"Vietnam Electricity\""
        )
        return

    thinking = await message.answer(
        f"🔎 urlscan.io scan — keyword: '{keyword}'\n"
        f"⏳ Cap {max_results} results, fetching verdicts per hit..."
    )
    await message.bot.send_chat_action(message.chat.id, ChatAction.TYPING)

    try:
        sightings = await search_brand(keyword, domain, max_results=max_results)
    except UrlscanConfigError as e:
        await thinking.delete()
        await message.answer(f"⚠️ Config lỗi: {e}")
        return
    except UrlscanAPIError as e:
        await thinking.delete()
        await message.answer(f"⚠️ API lỗi: {str(e)[:200]}")
        return
    except Exception as e:
        await thinking.delete()
        logger.exception("Scan failed")
        await message.answer(f"⚠️ Scan lỗi: {str(e)[:200]}")
        return
    await thinking.delete()

    if not sightings:
        await message.answer(f"📭 Không tìm thấy URL nào cho '{keyword}'.")
        return

    stats = await ingest_brand_abuse(sightings)

    lines = [
        f"✅ urlscan.io scan complete — '{keyword}'",
        "",
        f"Total URLs returned: {len(sightings)}",
        f"Ingested new: {stats['new']}",
        f"Updated: {stats['updated']}",
        "",
        "Pipeline stages:",
        f"  Typosquat matches: {stats['typosquat_matched']}",
        f"  Rule engine matches: {stats['rule_matched']}",
        f"  LLM classifier calls: {stats['llm_calls']}",
        f"  LLM confirmed relevant: {stats['llm_relevant']}",
        "",
        f"Findings created: {stats['findings_created']}",
        f"Queued for Bot 1 alert: {stats.get('queued_for_alert', 0)}",
    ]
    if stats.get("queued_for_alert", 0) > 0:
        lines.append("")
        lines.append("🚨 Bot 1 sẽ dispatch alert trong vòng 5s tới.")
    await message.answer("\n".join(lines))
