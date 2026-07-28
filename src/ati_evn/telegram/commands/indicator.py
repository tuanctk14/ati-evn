"""/indicator <id> — detail view of one ThreatIndicator."""
from __future__ import annotations

import logging

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message

from ati_evn.db.models import Customer, ThreatIndicator
from ati_evn.db.session import async_session
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command
from ati_evn.telegram.formatter.alert import format_indicator_alert

router = Router()
logger = logging.getLogger("ati_evn.telegram.indicator")


@router.message(Command("indicator"))
@log_command("indicator")
async def cmd_indicator(message: Message):
    args = parse_args(message.text or "", "indicator")
    pos = args.get("_positional", [])
    if not pos:
        await message.answer("Cú pháp: /indicator <id>")
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

        customer_name = "(orphan)"
        if ti.customer_id:
            c = await session.get(Customer, ti.customer_id)
            if c:
                customer_name = f"{c.name} ({c.short_code})"

    detail = format_indicator_alert(ti, customer_name)

    extras = ["", "─── DETAIL ───"]
    extras.append(f"Customer: {customer_name}")
    extras.append(f"First seen: {ti.first_seen.isoformat() if ti.first_seen else '-'}")
    extras.append(f"Last seen: {ti.last_seen.isoformat() if ti.last_seen else '-'}")
    extras.append(f"Expires at: {ti.expires_at.isoformat() if ti.expires_at else '-'}")
    extras.append(f"Status: {ti.status}")
    extras.append(f"Sources: {', '.join(ti.sources or [])} ({ti.source_count})")

    if ti.acknowledged_at:
        extras.append(
            f"Acknowledged: {ti.acknowledged_at.isoformat()} by {ti.acknowledged_by or '-'}"
        )
        if ti.acknowledgement_note:
            extras.append(f"  Note: {ti.acknowledgement_note[:200]}")

    notes = ti.notes or []
    if notes:
        extras.append(f"Notes ({len(notes)}):")
        for n in notes[-3:]:
            extras.append(f"  [{n.get('timestamp', '')[:19]}] {n.get('author', '?')}: {n.get('text', '')[:120]}")

    await message.answer(detail + "\n".join(extras), disable_web_page_preview=True)
