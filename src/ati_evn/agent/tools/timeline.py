"""timeline — aggregated recent-event feed for a customer."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import or_, select

from ati_evn.agent.tools._base import register_tool, tool_error
from ati_evn.db.models import AlertQueue, CommandLog, Customer, CustomerAsset, Finding
from ati_evn.db.query_utils import cve_only_filter, customer_name_or_code_match
from ati_evn.db.session import async_session

EVENT_CAP = 50


async def _resolve_customer(session, query_str: str) -> Customer | None:
    if query_str.isdigit():
        return await session.get(Customer, int(query_str))
    result = await session.execute(select(Customer).where(customer_name_or_code_match(query_str)).limit(1))
    return result.scalar_one_or_none()


@register_tool(
    name="timeline",
    description="Aggregated recent-event timeline for a customer: new findings, dispatched alerts, closures/reopens, rescans, asset additions.",
    parameters={
        "type": "object",
        "properties": {
            "customer": {"type": "string", "description": "Customer name or ID"},
            "since_days": {"type": "integer", "description": "Window size in days", "default": 30},
        },
        "required": ["customer"],
    },
)
async def timeline(customer: str, since_days: int = 30) -> dict:
    async with async_session() as session:
        cust = await _resolve_customer(session, customer)
        if not cust:
            return tool_error(f"Customer '{customer}' not found", hint="Check the name spelling or try /customer.")

        cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)
        events: list[dict] = []

        finding_rows = await session.execute(
            select(Finding).where(
                cve_only_filter(), Finding.customer_id == cust.id, Finding.first_seen >= cutoff,
            )
        )
        for f in finding_rows.scalars():
            events.append({
                "timestamp": f.first_seen.isoformat(),
                "type": "finding_created",
                "description": f"Finding #{f.id} created: {f.title}",
                "finding_id": f.id,
                "severity": f.severity.value,
            })
            if f.closed_at and f.closed_at >= cutoff:
                events.append({
                    "timestamp": f.closed_at.isoformat(),
                    "type": f"finding_{f.status.value}",
                    "description": f"Finding #{f.id} {f.status.value} by {f.closed_by}: {f.closed_reason or ''}",
                    "finding_id": f.id,
                    "severity": f.severity.value,
                })

        alert_rows = await session.execute(
            select(AlertQueue).where(
                AlertQueue.customer_id == cust.id,
                AlertQueue.dispatched_at.is_not(None),
                AlertQueue.dispatched_at >= cutoff,
            )
        )
        for a in alert_rows.scalars():
            events.append({
                "timestamp": a.dispatched_at.isoformat(),
                "type": "alert_dispatched",
                "description": f"Alert #{a.id} dispatched for finding #{a.finding_id}: {a.dispatch_reason or ''}",
                "finding_id": a.finding_id,
                "alert_id": a.id,
            })

        cmd_rows = await session.execute(
            select(CommandLog).where(
                CommandLog.command == "rescan",
                CommandLog.created_at >= cutoff,
            )
        )
        for c in cmd_rows.scalars():
            args_str = str(c.args or {})
            if cust.name.lower() in args_str.lower() or not args_str.strip("{}"):
                events.append({
                    "timestamp": c.created_at.isoformat(),
                    "type": "rescan_triggered",
                    "description": f"Rescan triggered by user {c.telegram_username or c.telegram_user_id}",
                })

        asset_rows = await session.execute(
            select(CustomerAsset).where(
                CustomerAsset.customer_id == cust.id,
                CustomerAsset.created_at >= cutoff,
                or_(
                    CustomerAsset.discovery_source.ilike("%manual%"),
                ),
            )
        )
        for asset in asset_rows.scalars():
            events.append({
                "timestamp": asset.created_at.isoformat(),
                "type": "asset_added",
                "description": f"Asset #{asset.id} added: {asset.asset_value} ({asset.discovery_source})",
            })

        events.sort(key=lambda e: e["timestamp"], reverse=True)
        truncated = len(events) > EVENT_CAP
        events = events[:EVENT_CAP]

        return {
            "customer": cust.name,
            "window_days": since_days,
            "events": events,
            "event_count": len(events),
            "truncated": truncated,
        }
