"""search_exposures — search Censys-observed external exposures."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from ati_evn.agent.tools._base import register_tool, tool_error
from ati_evn.db.models import Customer, Exposure
from ati_evn.db.query_utils import customer_name_or_code_match
from ati_evn.db.session import async_session


@register_tool(
    name="search_exposures",
    description=(
        "Search Censys-observed external exposures (open ports, services). "
        "Filter by customer, service name, port, status. Each row is a raw "
        "observation; rule engine may or may not have flagged it as a Finding."
    ),
    parameters={
        "type": "object",
        "properties": {
            "customer": {"type": "string", "description": "customer name or short_code"},
            "service": {"type": "string", "description": "e.g. ssh, redis, http"},
            "port": {"type": "integer"},
            "status": {
                "type": "string",
                "enum": ["active", "disappeared", "stale"],
                "default": "active",
            },
            "since_days": {"type": "integer"},
            "limit": {"type": "integer", "default": 10},
        },
        "required": [],
    },
)
async def search_exposures(
    customer: str | None = None,
    service: str | None = None,
    port: int | None = None,
    status: str = "active",
    since_days: int | None = None,
    limit: int = 10,
) -> dict:
    limit = min(max(limit, 1), 20)

    async with async_session() as session:
        stmt = select(Exposure).where(Exposure.status == status)
        count_stmt = select(func.count(Exposure.id)).where(Exposure.status == status)

        if customer:
            r = await session.execute(
                select(Customer.id).where(customer_name_or_code_match(customer)).limit(1)
            )
            cid = r.scalar_one_or_none()
            if not cid:
                return tool_error(f"Customer '{customer}' not found")
            stmt = stmt.where(Exposure.customer_id == cid)
            count_stmt = count_stmt.where(Exposure.customer_id == cid)
        if service:
            stmt = stmt.where(Exposure.service_name == service.lower())
            count_stmt = count_stmt.where(Exposure.service_name == service.lower())
        if port:
            stmt = stmt.where(Exposure.port == port)
            count_stmt = count_stmt.where(Exposure.port == port)
        if since_days:
            cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)
            stmt = stmt.where(Exposure.last_seen_local >= cutoff)
            count_stmt = count_stmt.where(Exposure.last_seen_local >= cutoff)

        total = (await session.execute(count_stmt)).scalar() or 0
        stmt = stmt.order_by(Exposure.last_seen_local.desc()).limit(limit)
        rows = list((await session.execute(stmt)).scalars())

        customer_names: dict[int, str] = {}
        for r in rows:
            if r.customer_id and r.customer_id not in customer_names:
                c = await session.get(Customer, r.customer_id)
                customer_names[r.customer_id] = c.name if c else f"#{r.customer_id}"

        return {
            "total_count": total,
            "returned_count": len(rows),
            "exposures": [
                {
                    "id": r.id, "ip": r.ip, "port": r.port,
                    "service": r.service_name,
                    "product": r.product, "version": r.version,
                    "customer": customer_names.get(r.customer_id),
                    "asset_id": r.asset_id,
                    "tls_version": r.tls_version,
                    "auth_required": r.auth_required,
                    "asn": r.asn,
                    "first_seen_local": r.first_seen_local.isoformat() if r.first_seen_local else None,
                    "last_seen_local": r.last_seen_local.isoformat() if r.last_seen_local else None,
                    "capabilities": r.capabilities or {},
                }
                for r in rows
            ],
        }
