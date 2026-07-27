"""Create a new Customer via agent."""
from __future__ import annotations

from sqlalchemy import select

from ati_evn.agent.tools._action_base import pending_confirmation, register_action_tool
from ati_evn.agent.tools._base import tool_error
from ati_evn.db.models import Customer
from ati_evn.db.session import async_session


@register_action_tool(
    name="add_customer",
    destructive=True,
    description="Create a new Customer (EVN subsidiary). Name must be unique.",
    parameters={
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "parent": {"type": "string", "description": "Parent customer name, optional"},
            "domain": {"type": "string", "description": "primary_domain, optional"},
            "short_code": {"type": "string"},
            "tier": {"type": "string", "enum": ["critical", "high", "medium"], "default": "medium"},
        },
        "required": ["name"],
    },
)
async def add_customer(
    name: str, parent: str | None = None, domain: str | None = None,
    short_code: str | None = None, tier: str = "medium",
    confirmed: bool = False,
) -> dict:
    async with async_session() as session:
        existing = await session.execute(select(Customer).where(Customer.name == name))
        row = existing.scalar_one_or_none()
        if row:
            if row.deleted_at:
                return tool_error(f"Customer '{name}' đã tồn tại nhưng đang bị soft-delete. Dùng /restore_customer.")
            return tool_error(f"Customer '{name}' đã tồn tại.")

        parent_id = None
        if parent:
            stmt = select(Customer.id).where(Customer.name == parent, Customer.deleted_at.is_(None))
            pr = (await session.execute(stmt)).scalar_one_or_none()
            if not pr:
                return tool_error(f"Parent '{parent}' không tồn tại.")
            parent_id = pr

    if not confirmed:
        return pending_confirmation({
            "action": "add_customer",
            "name": name,
            "parent": parent,
            "domain": domain,
            "short_code": short_code,
            "tier": tier,
        })

    async with async_session() as session:
        c = Customer(
            name=name, parent_id=parent_id,
            primary_domain=domain, short_code=short_code,
            tier=tier, industry="electric_utility",
            onboarding_state="created",
        )
        session.add(c)
        await session.commit()
        await session.refresh(c)
        return {"status": "created", "customer_id": c.id, "name": name}
