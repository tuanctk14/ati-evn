"""/scan_ghwarfare --keyword=X [--max=50] — on-demand document leak scan."""
from __future__ import annotations

import logging

from aiogram import Router
from aiogram.enums import ChatAction
from aiogram.filters import Command
from aiogram.types import Message

from ati_evn.external.document_ingest import ingest_documents
from ati_evn.external.grayhat_client import GrayhatAPIError, GrayhatConfigError, search_keyword
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command

logger = logging.getLogger("ati_evn.telegram.scan_ghwarfare")
router = Router()


@router.message(Command("scan_ghwarfare"))
@log_command("scan_ghwarfare")
async def cmd_scan_ghwarfare(message: Message):
    args = parse_args(message.text or "", "scan_ghwarfare")
    keyword = args.get("keyword")
    max_files = int(args.get("max") or 50)
    if not keyword:
        await message.answer(
            "Cú pháp: /scan_ghwarfare --keyword=X [--max=50]\n"
            "Ví dụ: /scan_ghwarfare --keyword=EVN"
        )
        return

    thinking = await message.answer(
        f"🔎 GrayHatWarfare scan — keyword: '{keyword}'\n"
        f"⏳ Free tier ~15% index, cap {max_files} files..."
    )
    await message.bot.send_chat_action(message.chat.id, ChatAction.TYPING)

    try:
        files = await search_keyword(keyword, max_files=max_files)
    except GrayhatConfigError as e:
        await thinking.delete()
        await message.answer(f"⚠️ Config lỗi: {e}")
        return
    except GrayhatAPIError as e:
        await thinking.delete()
        await message.answer(f"⚠️ API lỗi: {str(e)[:200]}")
        return
    except Exception as e:
        await thinking.delete()
        logger.exception("Scan failed")
        await message.answer(f"⚠️ Scan lỗi: {str(e)[:200]}")
        return
    await thinking.delete()

    if not files:
        await message.answer(f"📭 Không tìm thấy file nào cho '{keyword}'.")
        return

    stats = await ingest_documents(files)

    lines = [
        f"✅ GrayHatWarfare scan complete — '{keyword}'",
        "",
        f"Total files returned: {len(files)}",
        f"Ingested new: {stats['new']}",
        f"Updated: {stats['updated']}",
        "",
        "Pipeline stages:",
        f"  Bucket whitelist pass: {stats['whitelisted']}",
        f"  Rule engine matches: {stats['rule_matched']}",
        f"  LLM classifier calls: {stats['llm_calls']}",
        f"  LLM confirmed relevant: {stats['llm_relevant']}",
        "",
        f"Indicators created: {stats['indicators_created']}",
        f"Queued for Bot 1 alert: {stats.get('queued_for_alert', 0)}",
    ]
    if stats.get("queued_for_alert", 0) > 0:
        lines.append("")
        lines.append("🚨 Bot 1 sẽ dispatch alert trong vòng 5s tới.")
    await message.answer("\n".join(lines))
