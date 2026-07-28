"""/restore_customer <id|name> [--with-assets]

Restores a soft-deleted customer. By default assets stay deleted (matches
the confirmed design: restoring a customer doesn't silently reactivate
whatever asset set it had before). --with-assets also restores every
asset tagged with this customer's orphan marker.
"""
from __future__ import annotations

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message
from sqlalchemy import select

from ati_evn.db.models import Customer, CustomerAsset
from ati_evn.db.query_utils import customer_name_or_code_match
from ati_evn.db.session import async_session
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command

router = Router()


@router.message(Command("restore_customer"))
@log_command("restore_customer")
async def cmd_restore_customer(message: Message):
    args = parse_args(message.text or "", "restore_customer")
    pos = args.get("_positional", [])
    if not pos:
        await message.answer("Cú pháp: /restore_customer <id|name> [--with-assets]")
        return
    query_str = " ".join(pos)
    with_assets = bool(args.get("with-assets"))

    async with async_session() as session:
        c = None
        if query_str.isdigit():
            c = await session.get(Customer, int(query_str))
        if c is None:
            result = await session.execute(select(Customer).where(customer_name_or_code_match(query_str)))
            c = result.scalar_one_or_none()
        if not c:
            await message.answer(f"Không tìm thấy customer: {query_str}")
            return
        if not c.deleted_at:
            await message.answer(f"Customer #{c.id} đang active (chưa bị delete).")
            return

        live_collision = await session.execute(
            select(Customer).where(Customer.name == c.name, Customer.deleted_at.is_(None))
        )
        if live_collision.scalar_one_or_none():
            await message.answer(
                f"Không thể restore: đã có customer active khác tên '{c.name}'. "
                f"Đổi tên customer đó trước."
            )
            return

        c.deleted_at = None
        c.deleted_by = None

        restored_count = 0
        if with_assets:
            marker = f"[orphan_from_customer:{c.id}]"
            assets_result = await session.execute(
                select(CustomerAsset).where(
                    CustomerAsset.customer_id == c.id,
                    CustomerAsset.deleted_at.is_not(None),
                    CustomerAsset.notes.ilike(f"%{marker}%"),
                )
            )
            for asset in assets_result.scalars():
                asset.deleted_at = None
                asset.deleted_by = None
                if asset.notes:
                    asset.notes = asset.notes.replace(marker, "").strip() or None
                restored_count += 1

        await session.commit()
        customer_id, customer_name = c.id, c.name

    reply = f'✅ Customer #{customer_id} "{customer_name}" đã restore.'
    if with_assets:
        reply += f"\nAssets restored: {restored_count}"
    await message.answer(reply)
