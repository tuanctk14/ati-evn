"""Add a CustomerAsset via agent.

Reuses /add_asset logic. After insert, triggers a background rescan so
newly-matched findings can be created (Bot 1 will dispatch if applicable).
"""
from __future__ import annotations

from sqlalchemy import select

from ati_evn.agent.tools._action_base import pending_confirmation, register_action_tool
from ati_evn.agent.tools._base import tool_error
from ati_evn.db.models import AssetType, Customer, CustomerAsset, DeviceType, NetworkSegment
from ati_evn.db.query_utils import customer_name_or_code_match
from ati_evn.db.session import async_session
from ati_evn.rescan import trigger_rescan_background

VALID_ASSET_TYPES = [t.value for t in AssetType]


@register_action_tool(
    name="add_customer_asset",
    destructive=True,
    description=(
        "Add a monitored asset (ip/cidr/domain/subdomain/email/keyword/"
        "brand_name/org_name/tech_stack/device) to a Customer. Triggers a "
        "background rescan after insert -- newly-matched findings may appear."
    ),
    parameters={
        "type": "object",
        "properties": {
            "customer": {"type": "string"},
            "asset_type": {"type": "string", "enum": VALID_ASSET_TYPES},
            "value": {"type": "string", "description": "asset_value (required unless type=device with vendor+product)"},
            "vendor": {"type": "string"},
            "product": {"type": "string"},
            "version": {"type": "string"},
            "device_type": {"type": "string"},
            "network_segment": {"type": "string"},
            "criticality": {"type": "string", "enum": ["critical", "high", "medium", "low"], "default": "medium"},
            "is_ics": {"type": "boolean", "default": False},
            "is_internet_facing": {"type": "boolean", "default": False},
        },
        "required": ["customer", "asset_type"],
    },
)
async def add_customer_asset(
    customer: str, asset_type: str, value: str | None = None,
    vendor: str | None = None, product: str | None = None, version: str | None = None,
    device_type: str | None = None, network_segment: str | None = None,
    criticality: str = "medium", is_ics: bool = False, is_internet_facing: bool = False,
    confirmed: bool = False,
) -> dict:
    try:
        a_type = AssetType(asset_type.lower())
    except ValueError:
        return tool_error(f"asset_type không hợp lệ: {asset_type}. Valid: {VALID_ASSET_TYPES}")

    d_type = None
    if device_type:
        try:
            d_type = DeviceType(device_type.lower())
        except ValueError:
            return tool_error(f"device_type không hợp lệ: {device_type}")

    n_segment = None
    if network_segment:
        try:
            n_segment = NetworkSegment(network_segment.lower())
        except ValueError:
            return tool_error(f"network_segment không hợp lệ: {network_segment}")

    asset_value = value
    if not asset_value:
        if a_type == AssetType.DEVICE and vendor and product:
            asset_value = f"{vendor.lower()} {product.lower()}"
        else:
            return tool_error("Cần 'value' hoặc (vendor + product) cho asset_type=device")

    async with async_session() as session:
        row = await session.execute(
            select(Customer).where(customer_name_or_code_match(customer), Customer.deleted_at.is_(None))
        )
        cust = row.scalar_one_or_none()
        if not cust:
            return tool_error(f"Customer '{customer}' không tồn tại hoặc đã bị soft-delete.")
        customer_id, customer_name = cust.id, cust.name

    if not confirmed:
        return pending_confirmation({
            "action": "add_customer_asset",
            "customer": customer_name,
            "asset_type": a_type.value,
            "value": asset_value,
            "vendor": vendor,
            "product": product,
            "criticality": criticality,
        })

    async with async_session() as session:
        asset = CustomerAsset(
            customer_id=customer_id,
            asset_type=a_type,
            asset_value=asset_value,
            vendor=vendor,
            product=product,
            version=version,
            device_type=d_type,
            network_segment=n_segment,
            criticality=criticality.lower(),
            is_ics=is_ics,
            is_internet_facing=is_internet_facing,
            discovery_source="agent_tool",
        )
        session.add(asset)
        await session.commit()
        await session.refresh(asset)
        asset_id = asset.id

    trigger_rescan_background(
        reason=f"add_customer_asset via agent — asset#{asset_id}",
        focus_vendor=vendor.lower() if vendor else None,
    )

    return {
        "status": "created",
        "asset_id": asset_id,
        "customer": customer_name,
        "asset_type": a_type.value,
        "value": asset_value,
        "rescan_queued": True,
    }
