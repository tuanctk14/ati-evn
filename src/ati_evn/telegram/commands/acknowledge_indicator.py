"""/acknowledge_indicator <id> [--note=<text>]"""
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
logger = logging.getLogger("ati_evn.telegram.acknowledge_indicator")


@router.message(Command("acknowledge_indicator"))
@log_command("acknowledge_indicator")
async def cmd_acknowledge_indicator(message: Message):
    args = parse_args(message.text or "", "acknowledge_indicator")
    pos = args.get("_positional", [])
    note = args.get("note", "")

    if not pos:
        await message.answer("Cú pháp: /acknowledge_indicator <id> [--note=<text>]")
        return

    try:
        ti_id = int(pos[0])
    except ValueError:
        await message.answer("⚠️ ID phải là số nguyên.")
        return

    async with async_session() as session:
        ti = await session.get(ThreatIndicator, ti_id)
        if not ti:
            await message.answer(f"⚠️ ThreatIndicator #{ti_id} không tồn tại.")
            return

        if ti.acknowledged_at:
            await message.answer(
                f"ℹ️ TI #{ti_id} đã được acknowledge trước đó "
                f"({ti.acknowledged_at.strftime('%Y-%m-%d %H:%M')})."
            )
            return

        now = datetime.now(timezone.utc)
        ti.acknowledged_at = now
        ti.acknowledged_by = str(message.from_user.id)
        if note:
            ti.acknowledgement_note = note[:500]
        ti.status = "acknowledged"
        ti.updated_at = now
        await session.commit()

        indicator_type = ti.indicator_type
        title = ti.title

    register_command_tool_call(
        message, tool_name="acknowledge_indicator",
        output_summary=f"TI #{ti_id} ({indicator_type}) acknowledged",
        entity_ids=[ti_id],
    )
    await message.answer(f"✓ Acknowledged TI #{ti_id} — {indicator_type}: {title[:80]}.")
