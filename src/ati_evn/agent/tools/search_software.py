"""search_software — find which customers run a given vendor/product/version."""
from __future__ import annotations

from sqlalchemy import func, select

from ati_evn.agent.tools._base import register_tool
from ati_evn.db.models import Customer, CustomerAsset
from ati_evn.db.query_utils import only_live_asset, only_live_customer
from ati_evn.db.session import async_session

HARD_CAP = 20


@register_tool(
    name="search_software",
    description=(
        "Find which customers run a given vendor/product/version combination "
        "across their live assets. E.g. 'who is running Apache 2.4.49?'"
    ),
    parameters={
        "type": "object",
        "properties": {
            "vendor": {"type": "string", "description": "Vendor name, e.g. 'fortinet'"},
            "product": {"type": "string", "description": "Product name, e.g. 'fortios'"},
            "version": {"type": "string", "description": "Exact version string, e.g. '7.2.4'"},
        },
        "required": [],
    },
)
async def search_software(
    vendor: str | None = None,
    product: str | None = None,
    version: str | None = None,
) -> dict:
    async with async_session() as session:
        stmt = select(CustomerAsset, Customer.name).join(
            Customer, Customer.id == CustomerAsset.customer_id,
        ).where(only_live_asset(), only_live_customer())

        if vendor:
            stmt = stmt.where(CustomerAsset.vendor.ilike(f"%{vendor}%"))
        if product:
            stmt = stmt.where(CustomerAsset.product.ilike(f"%{product}%"))
        if version:
            stmt = stmt.where(CustomerAsset.version == version)

        count_stmt = select(func.count()).select_from(stmt.subquery())
        total_count = (await session.execute(count_stmt)).scalar_one()

        stmt = stmt.limit(HARD_CAP)
        rows = (await session.execute(stmt)).all()

        by_customer: dict[str, list[dict]] = {}
        for asset, cust_name in rows:
            by_customer.setdefault(cust_name, []).append({
                "id": asset.id,
                "vendor": asset.vendor,
                "product": asset.product,
                "version": asset.version,
                "asset_value": asset.asset_value,
                "criticality": asset.criticality,
            })

    return {
        "total_count": total_count,
        "returned_count": len(rows),
        "assets_by_customer": by_customer,
    }
