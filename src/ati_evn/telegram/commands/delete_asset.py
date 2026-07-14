"""/delete_asset <id> --confirm

Soft-delete. Related Findings are left untouched (evidence retained; they
still reference the asset by value, formatter handles orphan lookups
gracefully).
"""
from __future__ import annotations

from datetime import datetime, timezone

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message

from ati_evn.db.models import CustomerAsset
from ati_evn.db.session import async_session
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command

router = Router()


@router.message(Command("delete_asset"))
@log_command("delete_asset")
async def cmd_delete_asset(message: Message):
    args = parse_args(message.text or "", "delete_asset")
    pos = args.get("_positional", [])
    if not pos or not args.get("confirm"):
        await message.answer("Cú pháp: /delete_asset <id> --confirm")
        return
    try:
        asset_id = int(pos[0])
    except ValueError:
        await message.answer(f"asset_id không hợp lệ: {pos[0]}")
        return
    who = message.from_user.username or str(message.from_user.id)

    async with async_session() as session:
        asset = await session.get(CustomerAsset, asset_id)
        if not asset:
            await message.answer(f"Không tìm thấy Asset #{asset_id}")
            return
        if asset.deleted_at:
            await message.answer(f"Asset #{asset_id} đã bị soft-delete từ trước.")
            return

        asset.deleted_at = datetime.now(timezone.utc)
        asset.deleted_by = who
        label = asset.asset_value
        if asset.vendor and asset.product:
            label = f"{asset.asset_value} ({asset.vendor} {asset.product}"
            label += f" v{asset.version})" if asset.version else ")"
        await session.commit()

    await message.answer(
        f'✅ Asset #{asset_id} "{label}" đã soft-delete.\n'
        f"Restore: /restore_asset {asset_id}"
    )
