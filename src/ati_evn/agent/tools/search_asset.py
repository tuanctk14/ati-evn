"""search_asset — filtered list of live CustomerAssets."""
from __future__ import annotations

from sqlalchemy import func, select

from ati_evn.agent.tools._base import register_tool
from ati_evn.db.models import Customer, CustomerAsset, Finding, FindingStatus
from ati_evn.db.query_utils import customer_name_or_code_match, only_live_asset, only_live_customer
from ati_evn.db.session import async_session

HARD_CAP = 20


@register_tool(
    name="search_asset",
    description=(
        "Search live CustomerAssets, optionally filtered by customer, "
        "vendor, product, or asset_value (the asset's own identifying "
        "value -- hostname, IP, domain, keyword, etc., e.g. 'evn-web-01' "
        "or 'evn.io.vn'). There is no separate lookup-by-value tool -- "
        "use asset_value here for 'does asset/domain/IP X have any "
        "findings' questions rather than assuming a dedicated tool "
        "exists for that."
    ),
    parameters={
        "type": "object",
        "properties": {
            "customer": {"type": "string", "description": "Customer name (partial match)"},
            "vendor": {"type": "string", "description": "Vendor name (partial match)"},
            "product": {"type": "string", "description": "Product name (partial match)"},
            "asset_value": {"type": "string", "description": "Asset's identifying value (partial match) -- hostname, IP, domain, keyword, etc."},
            "is_internet_facing": {"type": "boolean", "description": "Filter to assets exposed to the internet (true) or not (false). Omit for no filter."},
            "limit": {"type": "integer", "description": "Max rows (capped at 20)", "default": 20},
        },
        "required": [],
    },
)
async def search_asset(
    customer: str | None = None,
    vendor: str | None = None,
    product: str | None = None,
    asset_value: str | None = None,
    is_internet_facing: bool | None = None,
    limit: int = 20,
) -> dict:
    limit = min(limit or 20, HARD_CAP)

    async with async_session() as session:
        stmt = select(CustomerAsset, Customer.name).join(
            Customer, Customer.id == CustomerAsset.customer_id,
        ).where(only_live_asset(), only_live_customer())

        if customer:
            stmt = stmt.where(customer_name_or_code_match(customer))
        if vendor:
            stmt = stmt.where(CustomerAsset.vendor.ilike(f"%{vendor}%"))
        if product:
            stmt = stmt.where(CustomerAsset.product.ilike(f"%{product}%"))
        if asset_value:
            stmt = stmt.where(CustomerAsset.asset_value.ilike(f"%{asset_value}%"))
        if is_internet_facing is not None:
            stmt = stmt.where(CustomerAsset.is_internet_facing == is_internet_facing)

        count_stmt = select(func.count()).select_from(stmt.subquery())
        total_count = (await session.execute(count_stmt)).scalar_one()

        stmt = stmt.limit(limit)
        rows = (await session.execute(stmt)).all()

        assets = []
        for asset, cust_name in rows:
            open_count = (await session.execute(
                select(func.count()).select_from(Finding).where(
                    Finding.customer_id == asset.customer_id,
                    Finding.matched_asset == asset.asset_value,
                    Finding.status == FindingStatus.OPEN,
                )
            )).scalar_one()
            assets.append({
                "id": asset.id,
                "customer_name": cust_name,
                "asset_type": asset.asset_type.value,
                "vendor": asset.vendor,
                "product": asset.product,
                "version": asset.version,
                "device_type": asset.device_type.value if asset.device_type else None,
                "network_segment": asset.network_segment.value if asset.network_segment else None,
                "criticality": asset.criticality,
                "is_ics": asset.is_ics,
                "is_internet_facing": asset.is_internet_facing,
                "open_finding_count": open_count,
            })

    return {
        "total_count": total_count,
        "returned_count": len(assets),
        "assets": assets,
    }
