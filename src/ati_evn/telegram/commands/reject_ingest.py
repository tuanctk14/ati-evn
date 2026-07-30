"""/reject_ingest <session_id> [--reason=X]"""
from __future__ import annotations

from datetime import datetime, timezone

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message

from ati_evn.db.models import IngestionSession
from ati_evn.db.session import async_session
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command, register_command_tool_call

router = Router()


@router.message(Command("reject_ingest"))
@log_command("reject_ingest")
async def cmd_reject_ingest(message: Message):
    args = parse_args(message.text or "", "reject_ingest")
    pos = args.get("_positional", [])
    reason = args.get("reason")
    if not pos:
        await message.answer("Cú pháp: /reject_ingest <id> [--reason=X]")
        return
    try:
        sid = int(pos[0])
    except ValueError:
        await message.answer(f"session_id không hợp lệ: {pos[0]}")
        return
    who = message.from_user.username or str(message.from_user.id)

    async with async_session() as session:
        ingest = await session.get(IngestionSession, sid)
        if not ingest:
            await message.answer(f"Session #{sid} không tồn tại.")
            return
        if ingest.status != "pending":
            await message.answer(
                f"Session #{sid} status={ingest.status}, chỉ pending mới reject được."
            )
            return
        ingest.status = "rejected"
        ingest.rejected_at = datetime.now(timezone.utc)
        ingest.rejected_reason = reason or f"Rejected by @{who}"
        await session.commit()
    register_command_tool_call(
        message, tool_name="reject_ingest",
        output_summary=f"Session #{sid} rejected by @{who}",
        entity_ids=[sid],
    )
    await message.answer(
        f"❌ Session #{sid} REJECTED by @{who}" + (f"\nReason: {reason}" if reason else "")
    )
