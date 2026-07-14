"""/rescan [--customer=X] [--asset=id] — trigger async rescan.

Reply immediately with "queued", let Bot 1 notify results.
"""
from __future__ import annotations

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message

from ati_evn.rescan import trigger_rescan_background
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command

router = Router()


@router.message(Command("rescan"))
@log_command("rescan")
async def cmd_rescan(message: Message):
    args = parse_args(message.text or "", "rescan")
    customer = args.get("customer")
    asset_id = args.get("asset")
    who = message.from_user.username or str(message.from_user.id)

    trigger_rescan_background(
        reason=f"Manual /rescan by @{who}",
        focus_vendor=None,
        bot=message.bot,
        chat_id=message.chat.id,
    )

    scope = "toàn hệ thống"
    if customer:
        scope = f"customer={customer}"
    if asset_id:
        scope = f"asset={asset_id}"
    await message.answer(
        f"🔍 Rescan đã queue ({scope}).\n"
        f"Sẽ báo kết quả ở đây khi quét xong (kể cả khi không có match mới)."
    )
