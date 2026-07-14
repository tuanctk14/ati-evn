"""/restore_asset <id>

Restores a soft-deleted asset (its customer must be live) and fires an
auto-rescan since the newly-live asset may match existing detections.
"""
from __future__ import annotations

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message

from ati_evn.db.models import Customer, CustomerAsset
from ati_evn.db.session import async_session
from ati_evn.rescan import trigger_rescan_background
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command

router = Router()


@router.message(Command("restore_asset"))
@log_command("restore_asset")
async def cmd_restore_asset(message: Message):
    args = parse_args(message.text or "", "restore_asset")
    pos = args.get("_positional", [])
    if not pos:
        await message.answer("Cú pháp: /restore_asset <id>")
        return
    try:
        asset_id = int(pos[0])
    except ValueError:
        await message.answer(f"asset_id không hợp lệ: {pos[0]}")
        return

    async with async_session() as session:
        asset = await session.get(CustomerAsset, asset_id)
        if not asset:
            await message.answer(f"Không tìm thấy Asset #{asset_id}")
            return
        if not asset.deleted_at:
            await message.answer(f"Asset #{asset_id} đang active (chưa bị delete).")
            return

        customer = await session.get(Customer, asset.customer_id)
        if customer and customer.deleted_at:
            await message.answer(
                f"Customer của asset này đang bị delete. Restore customer trước."
            )
            return

        asset.deleted_at = None
        asset.deleted_by = None
        vendor_for_rescan = (asset.vendor or "").lower() if asset.vendor else None

        await session.commit()
        asset_id_final = asset.id

    trigger_rescan_background(
        reason=f"/restore_asset #{asset_id_final}",
        focus_vendor=vendor_for_rescan,
        bot=message.bot,
        chat_id=message.chat.id,
    )
    await message.answer(f"✅ Asset #{asset_id_final} restored. Rescan đã queue.")
