"""/confirm_campaign and /reject_campaign — state transitions."""
from datetime import datetime, timezone

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message

from ati_evn.db.models import Campaign
from ati_evn.db.session import async_session
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command

router = Router()


@router.message(Command("confirm_campaign"))
@log_command("confirm_campaign")
async def cmd_confirm_campaign(message: Message):
    args = parse_args(message.text or "", "confirm_campaign")
    pos = args.get("_positional", [])
    notes = args.get("notes")
    if not pos:
        await message.answer("Cú pháp: /confirm_campaign <id> [--notes=X]")
        return
    try:
        cid = int(pos[0])
    except ValueError:
        await message.answer(f"ID không hợp lệ: {pos[0]}")
        return
    who = message.from_user.username or str(message.from_user.id)

    async with async_session() as session:
        campaign = await session.get(Campaign, cid)
        if not campaign:
            await message.answer(f"Không tìm thấy Campaign #{cid}")
            return
        if campaign.status != "candidate":
            await message.answer(
                f"Campaign #{cid} status={campaign.status}, "
                f"chỉ candidate mới confirm được."
            )
            return
        campaign.status = "confirmed"
        campaign.reviewed_by = who
        campaign.reviewed_at = datetime.now(timezone.utc)
        campaign.review_notes = notes
        campaign.updated_at = datetime.now(timezone.utc)
        await session.commit()
    await message.answer(
        f"✅ Campaign #{cid} CONFIRMED by @{who}"
        + (f"\nNotes: {notes}" if notes else "")
    )


@router.message(Command("reject_campaign"))
@log_command("reject_campaign")
async def cmd_reject_campaign(message: Message):
    args = parse_args(message.text or "", "reject_campaign")
    pos = args.get("_positional", [])
    reason = args.get("reason")
    if not pos or not reason:
        await message.answer("Cú pháp: /reject_campaign <id> --reason=X")
        return
    try:
        cid = int(pos[0])
    except ValueError:
        await message.answer(f"ID không hợp lệ: {pos[0]}")
        return
    who = message.from_user.username or str(message.from_user.id)

    async with async_session() as session:
        campaign = await session.get(Campaign, cid)
        if not campaign:
            await message.answer(f"Không tìm thấy Campaign #{cid}")
            return
        if campaign.status != "candidate":
            await message.answer(
                f"Campaign #{cid} status={campaign.status}, "
                f"chỉ candidate mới reject được."
            )
            return
        campaign.status = "rejected"
        campaign.reviewed_by = who
        campaign.reviewed_at = datetime.now(timezone.utc)
        campaign.review_notes = reason
        campaign.updated_at = datetime.now(timezone.utc)
        await session.commit()
    await message.answer(
        f"⚪ Campaign #{cid} REJECTED by @{who}\nReason: {reason}"
    )
