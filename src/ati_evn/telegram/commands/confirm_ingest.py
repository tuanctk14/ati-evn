"""/confirm_ingest <session_id>

Materializes a pending IngestionSession: creates Detections, auto-fetches
missing CVEs from NVD, runs a scoped matcher pass, and reports results.
"""
from __future__ import annotations

import logging

from aiogram import Router
from aiogram.enums import ChatAction
from aiogram.filters import Command
from aiogram.types import Message

from ati_evn.ingestion.confirm import confirm_ingestion
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command

logger = logging.getLogger("ati_evn.telegram.confirm_ingest")
router = Router()


@router.message(Command("confirm_ingest"))
@log_command("confirm_ingest")
async def cmd_confirm_ingest(message: Message):
    args = parse_args(message.text or "", "confirm_ingest")
    pos = args.get("_positional", [])
    if not pos:
        await message.answer("Cú pháp: /confirm_ingest <session_id>")
        return
    try:
        sid = int(pos[0])
    except ValueError:
        await message.answer(f"session_id không hợp lệ: {pos[0]}")
        return

    thinking = await message.answer(
        f"📥 Đang import Session #{sid}...\n"
        f"  - Tạo Detection rows\n"
        f"  - Auto-fetch missing CVEs từ NVD\n"
        f"  - Chạy matcher scoped\n"
        f"⏳ Có thể mất 30-60s nếu có nhiều CVE mới."
    )
    await message.bot.send_chat_action(message.chat.id, ChatAction.TYPING)

    who = message.from_user.username or str(message.from_user.id)
    stats = await confirm_ingestion(sid, who)

    await thinking.delete()

    if "error" in stats:
        await message.answer(f"⚠️ Confirm failed: {stats['error']}")
        return

    lines = [
        f"✅ Session #{sid} confirmed",
        "",
        f"IOCs ingested: {stats['iocs_ingested']}",
        f"CVEs ingested: {stats['cves_ingested']}",
    ]
    if stats["cves_fetch_failed"]:
        failed = stats["cves_fetch_failed"]
        lines.append(
            f"⚠️ CVE fetch failed ({len(failed)}): "
            f"{', '.join(failed[:5])}" + ("..." if len(failed) > 5 else "")
        )
    lines.append(f"Detections created: {stats['detections_created']}")
    lines.append(f"Findings created: {stats['findings_created']}")

    if stats["finding_ids"]:
        ids = stats["finding_ids"]
        lines.append(f"\nFinding IDs: {ids[:10]}" + ("..." if len(ids) > 10 else ""))
        lines.append("\n🚨 Bot 1 sẽ dispatch alert cho findings đủ threshold.")
    else:
        lines.append(
            "\nℹ️ Không match asset EVN — Detections vẫn được lưu "
            "cho future rescan hoặc analyst reference."
        )

    await message.answer("\n".join(lines))
