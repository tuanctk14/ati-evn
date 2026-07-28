"""/delete_customer <id|name> --confirm="<full_name>"

Soft-delete. --confirm must exactly match the customer's current name
(case-sensitive) as the safety mechanism. Cascade rule C: soft-deleting a
customer also soft-deletes all its live assets, tagging each with an
orphan marker in `notes` so /restore_customer --with-assets can find them
again. Findings/Detections are left untouched — they're evidence.
"""
from __future__ import annotations

from datetime import datetime, timezone

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


@router.message(Command("delete_customer"))
@log_command("delete_customer")
async def cmd_delete_customer(message: Message):
    args = parse_args(message.text or "", "delete_customer")
    pos = args.get("_positional", [])
    confirm = args.get("confirm")
    if not pos or not confirm:
        await message.answer('Cú pháp: /delete_customer <id|name> --confirm="<full_name>"')
        return
    query_str = " ".join(pos)
    who = message.from_user.username or str(message.from_user.id)

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
        if c.deleted_at:
            await message.answer(f"Customer #{c.id} đã bị soft-delete từ trước.")
            return

        if confirm != c.name:
            await message.answer(
                f'--confirm không khớp. Cần đúng tên: "{c.name}" (case-sensitive)'
            )
            return

        child_check = await session.execute(
            select(Customer.id).where(Customer.parent_id == c.id, Customer.deleted_at.is_(None))
        )
        if child_check.first():
            await message.answer(
                f"Customer #{c.id} vẫn còn subsidiary đang active. "
                f"Xóa/reparent subsidiary trước."
            )
            return

        now = datetime.now(timezone.utc)
        c.deleted_at = now
        c.deleted_by = who

        assets_result = await session.execute(
            select(CustomerAsset).where(
                CustomerAsset.customer_id == c.id, CustomerAsset.deleted_at.is_(None),
            )
        )
        assets = list(assets_result.scalars())
        for asset in assets:
            asset.deleted_at = now
            asset.deleted_by = f"cascade from customer #{c.id}"
            marker = f"[orphan_from_customer:{c.id}]"
            asset.notes = f"{marker} {asset.notes}" if asset.notes else marker

        await session.commit()
        customer_id, customer_name = c.id, c.name
        asset_count = len(assets)

    await message.answer(
        f'✅ Customer #{customer_id} "{customer_name}" đã soft-delete '
        f"(cascade {asset_count} assets).\n"
        f"Restore: /restore_customer {customer_name} [--with-assets]"
    )
