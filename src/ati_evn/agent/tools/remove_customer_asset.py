"""Soft-delete a CustomerAsset via agent.

Related Findings are left untouched (evidence retained; they still
reference the asset by value).
"""
from __future__ import annotations

from datetime import datetime, timezone

from ati_evn.agent.tools._action_base import pending_confirmation, register_action_tool
from ati_evn.agent.tools._base import tool_error
from ati_evn.db.models import CustomerAsset
from ati_evn.db.session import async_session


@register_action_tool(
    name="remove_customer_asset",
    destructive=True,
    description="Soft-delete a CustomerAsset. Linked Findings are retained as evidence.",
    parameters={
        "type": "object",
        "properties": {"asset_id": {"type": "integer"}},
        "required": ["asset_id"],
    },
)
async def remove_customer_asset(asset_id: int, confirmed: bool = False) -> dict:
    async with async_session() as session:
        asset = await session.get(CustomerAsset, asset_id)
        if not asset:
            return tool_error(f"Asset #{asset_id} not found")
        if asset.deleted_at:
            return tool_error(f"Asset #{asset_id} đã bị soft-delete từ trước.")
        label = asset.asset_value
        asset_type = asset.asset_type.value

    if not confirmed:
        return pending_confirmation({
            "action": "remove_customer_asset",
            "asset_id": asset_id,
            "asset_type": asset_type,
            "value": label,
        })

    async with async_session() as session:
        a = await session.get(CustomerAsset, asset_id)
        if not a:
            return tool_error(f"Asset #{asset_id} not found")
        a.deleted_at = datetime.now(timezone.utc)
        a.deleted_by = "agent"
        await session.commit()

    return {"status": "deleted", "asset_id": asset_id, "value": label}
