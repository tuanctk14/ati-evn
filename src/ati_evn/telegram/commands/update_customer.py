"""/update_customer <id|name> [--name=X] [--parent=Y] [--domain=Z]
                    [--tier=X] [--short-code=X] [--active=true|false]
"""
from __future__ import annotations

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message
from sqlalchemy import select

from ati_evn.db.models import Customer
from ati_evn.db.query_utils import customer_name_or_code_match
from ati_evn.db.session import async_session
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command

router = Router()


async def _resolve_customer(session, query_str: str) -> Customer | None:
    if query_str.isdigit():
        return await session.get(Customer, int(query_str))
    result = await session.execute(select(Customer).where(customer_name_or_code_match(query_str)))
    return result.scalar_one_or_none()


async def _is_descendant(session, candidate_id: int, of_id: int) -> bool:
    """True if `candidate_id` is a descendant (or equal to) `of_id`, walking
    the parent chain upward from candidate_id."""
    current_id = candidate_id
    seen = set()
    while current_id is not None:
        if current_id == of_id:
            return True
        if current_id in seen:
            return False  # defensive: cycle already present, bail
        seen.add(current_id)
        row = await session.execute(select(Customer.parent_id).where(Customer.id == current_id))
        current_id = row.scalar_one_or_none()
    return False


@router.message(Command("update_customer"))
@log_command("update_customer")
async def cmd_update_customer(message: Message):
    args = parse_args(message.text or "", "update_customer")
    pos = args.get("_positional", [])
    if not pos:
        await message.answer(
            "Cú pháp: /update_customer <id|name> [--name=X] [--parent=Y] "
            "[--domain=Z] [--tier=X] [--short-code=X] [--active=true|false]"
        )
        return
    query_str = " ".join(pos)

    async with async_session() as session:
        c = await _resolve_customer(session, query_str)
        if not c:
            await message.answer(f"Không tìm thấy customer: {query_str}")
            return
        if c.deleted_at:
            await message.answer(f"Customer #{c.id} đang bị soft-delete. Restore trước khi update.")
            return

        changes: dict[str, tuple] = {}

        new_name = args.get("name")
        if new_name and new_name != c.name:
            existing = await session.execute(
                select(Customer).where(Customer.name == new_name, Customer.deleted_at.is_(None))
            )
            if existing.scalar_one_or_none():
                await message.answer(f"Tên '{new_name}' đã được dùng bởi customer khác.")
                return
            changes["name"] = (c.name, new_name)
            c.name = new_name

        new_parent = args.get("parent")
        if new_parent is not None:
            if new_parent == "":
                if c.parent_id is not None:
                    changes["parent"] = (c.parent_id, None)
                    c.parent_id = None
            else:
                parent = await _resolve_customer(session, new_parent)
                if not parent or parent.deleted_at:
                    await message.answer(f"Parent '{new_parent}' không tồn tại hoặc đã bị delete.")
                    return
                if parent.id == c.id:
                    await message.answer("Customer không thể là parent của chính nó.")
                    return
                if await _is_descendant(session, parent.id, c.id):
                    await message.answer(
                        f"Không thể set parent='{new_parent}': sẽ tạo vòng lặp "
                        f"(customer đó là con cháu của #{c.id})."
                    )
                    return
                if parent.id != c.parent_id:
                    changes["parent"] = (c.parent_id, parent.id)
                    c.parent_id = parent.id

        new_domain = args.get("domain")
        if new_domain and new_domain != c.primary_domain:
            changes["domain"] = (c.primary_domain, new_domain)
            c.primary_domain = new_domain

        new_tier = args.get("tier")
        if new_tier and new_tier != c.tier:
            changes["tier"] = (c.tier, new_tier)
            c.tier = new_tier

        new_short_code = args.get("short-code")
        if new_short_code and new_short_code != c.short_code:
            changes["short_code"] = (c.short_code, new_short_code)
            c.short_code = new_short_code

        new_active = args.get("active")
        if new_active is not None:
            active_bool = str(new_active).lower() in ("true", "1", "yes")
            if active_bool != c.active:
                changes["active"] = (c.active, active_bool)
                c.active = active_bool

        if not changes:
            await message.answer("Không có thay đổi.")
            return

        await session.commit()

    changes_str = "\n".join(f"  {k}: {v[0]} → {v[1]}" for k, v in changes.items())
    await message.answer(f"✅ Customer #{c.id} updated:\n{changes_str}")
