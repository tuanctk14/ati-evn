"""/note_indicator <id> <text> — append investigation note."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message

from ati_evn.db.models import ThreatIndicator
from ati_evn.db.session import async_session
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command, register_command_tool_call

router = Router()
logger = logging.getLogger("ati_evn.telegram.note_indicator")


@router.message(Command("note_indicator"))
@log_command("note_indicator")
async def cmd_note_indicator(message: Message):
    args = parse_args(message.text or "", "note_indicator")
    pos = args.get("_positional", [])
    if len(pos) < 2:
        await message.answer("Cú pháp: /note_indicator <id> <text of note>")
        return

    try:
        ti_id = int(pos[0])
    except ValueError:
        await message.answer("⚠️ ID phải là số nguyên.")
        return

    note_text = " ".join(pos[1:])[:800]
    if not note_text.strip():
        await message.answer("⚠️ Note không được rỗng.")
        return

    async with async_session() as session:
        ti = await session.get(ThreatIndicator, ti_id)
        if not ti:
            await message.answer(f"⚠️ TI #{ti_id} không tồn tại.")
            return

        notes = list(ti.notes or [])
        notes.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "author": str(message.from_user.id),
            "text": note_text,
        })
        ti.notes = notes[-50:]
        ti.updated_at = datetime.now(timezone.utc)
        await session.commit()
        total_notes = len(ti.notes)

    register_command_tool_call(
        message, tool_name="note_indicator",
        output_summary=f"Added note to TI #{ti_id} ({total_notes} total)",
        entity_ids=[ti_id],
    )
    await message.answer(f"📝 Added note to TI #{ti_id}. Total notes: {total_notes}.")
