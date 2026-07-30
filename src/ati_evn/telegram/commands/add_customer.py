"""/add_customer --name=X [--parent=Y] [--domain=Z] [--short-code=X]
                 [--tier=critical|high|medium]"""
from __future__ import annotations

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message
from sqlalchemy import select

from ati_evn.db.models import Customer
from ati_evn.db.session import async_session
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command, register_command_tool_call

router = Router()


@router.message(Command("add_customer"))
@log_command("add_customer")
async def cmd_add_customer(message: Message):
    args = parse_args(message.text or "", "add_customer")
    name = args.get("name")
    if not name:
        await message.answer(
            "Cú pháp: /add_customer --name=X [--parent=Y] [--domain=Z] "
            "[--short-code=X] [--tier=critical|high|medium]"
        )
        return
    parent_name = args.get("parent")
    primary_domain = args.get("domain")
    short_code = args.get("short-code")
    tier = args.get("tier") or "medium"

    async with async_session() as session:
        existing = await session.execute(select(Customer).where(Customer.name == name))
        row = existing.scalar_one_or_none()
        if row:
            if row.deleted_at:
                await message.answer(
                    f"Customer '{name}' đã tồn tại nhưng đang bị soft-delete.\n"
                    f"Dùng /restore_customer {name} để khôi phục."
                )
            else:
                await message.answer(f"Customer '{name}' đã tồn tại.")
            return

        parent_id = None
        if parent_name:
            stmt = select(Customer.id).where(
                Customer.name == parent_name, Customer.deleted_at.is_(None),
            )
            pr = (await session.execute(stmt)).scalar_one_or_none()
            if not pr:
                await message.answer(
                    f"Parent '{parent_name}' không tồn tại. "
                    f"Tạo parent trước hoặc bỏ flag --parent."
                )
                return
            parent_id = pr

        c = Customer(
            name=name, parent_id=parent_id,
            primary_domain=primary_domain, short_code=short_code,
            tier=tier, industry="electric_utility",
            onboarding_state="created",
        )
        session.add(c)
        await session.commit()
        register_command_tool_call(
            message, tool_name="add_customer",
            output_summary=f"Customer #{c.id} '{name}' created",
            entity_ids=[c.id],
        )
        await message.answer(
            f"✅ Đã tạo customer #{c.id}: {name}"
            + (f" (parent={parent_name})" if parent_name else "")
        )
