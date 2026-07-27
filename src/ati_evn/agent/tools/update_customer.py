"""Update Customer fields via agent."""
from __future__ import annotations

from sqlalchemy import select

from ati_evn.agent.tools._action_base import pending_confirmation, register_action_tool
from ati_evn.agent.tools._base import tool_error
from ati_evn.db.models import Customer
from ati_evn.db.query_utils import customer_name_or_code_match
from ati_evn.db.session import async_session


@register_action_tool(
    name="update_customer",
    destructive=True,
    description="Update Customer fields (domain, tier, short_code, active). Does not rename or reparent.",
    parameters={
        "type": "object",
        "properties": {
            "customer": {"type": "string", "description": "Customer name or short_code"},
            "domain": {"type": "string"},
            "tier": {"type": "string", "enum": ["critical", "high", "medium"]},
            "short_code": {"type": "string"},
            "active": {"type": "boolean"},
        },
        "required": ["customer"],
    },
)
async def update_customer(
    customer: str, domain: str | None = None, tier: str | None = None,
    short_code: str | None = None, active: bool | None = None,
    confirmed: bool = False,
) -> dict:
    async with async_session() as session:
        row = await session.execute(
            select(Customer).where(customer_name_or_code_match(customer), Customer.deleted_at.is_(None)).limit(1)
        )
        c = row.scalar_one_or_none()
        if not c:
            return tool_error(f"Customer '{customer}' not found")

        changes: dict[str, tuple] = {}
        if domain is not None and domain != c.primary_domain:
            changes["domain"] = (c.primary_domain, domain)
        if tier is not None and tier != c.tier:
            changes["tier"] = (c.tier, tier)
        if short_code is not None and short_code != c.short_code:
            changes["short_code"] = (c.short_code, short_code)
        if active is not None and active != c.active:
            changes["active"] = (c.active, active)

        if not changes:
            return {"status": "no_change", "customer_id": c.id}

        customer_id = c.id

    if not confirmed:
        return pending_confirmation({
            "action": "update_customer",
            "customer_id": customer_id,
            "changes": {k: {"from": v[0], "to": v[1]} for k, v in changes.items()},
        })

    async with async_session() as session:
        c = await session.get(Customer, customer_id)
        if not c:
            return tool_error(f"Customer #{customer_id} not found")
        if domain is not None:
            c.primary_domain = domain
        if tier is not None:
            c.tier = tier
        if short_code is not None:
            c.short_code = short_code
        if active is not None:
            c.active = active
        await session.commit()

    return {
        "status": "updated",
        "customer_id": customer_id,
        "changes": {k: {"from": v[0], "to": v[1]} for k, v in changes.items()},
    }
