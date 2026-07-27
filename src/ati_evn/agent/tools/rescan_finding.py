"""Re-run enrichment on an existing Finding via agent.

Schema note: Finding has no updated_at column -- rescan history is
tracked entirely inside metadata_ (JSON), same pattern as /silence.
"""
from __future__ import annotations

from datetime import datetime, timezone

from ati_evn.agent.tools._action_base import pending_confirmation, register_action_tool
from ati_evn.agent.tools._base import tool_error
from ati_evn.db.models import Finding
from ati_evn.db.session import async_session


@register_action_tool(
    name="rescan_finding",
    destructive=True,
    description=(
        "Re-run enrichment on an existing Finding (e.g. re-query IP "
        "reputation providers). Updates the Finding's metadata in place, "
        "does not duplicate it."
    ),
    parameters={
        "type": "object",
        "properties": {
            "finding_id": {"type": "integer"},
            "reenrich_ip": {"type": "boolean", "default": True, "description": "Re-run enrich_ip if IP finding"},
        },
        "required": ["finding_id"],
    },
)
async def rescan_finding(finding_id: int, reenrich_ip: bool = True, confirmed: bool = False) -> dict:
    async with async_session() as session:
        f = await session.get(Finding, finding_id)
        if not f:
            return tool_error(f"Finding #{finding_id} not found")
        title = f.title
        ioc_type = f.ioc_type
        ioc_value = f.ioc_value

    will_reenrich_ip = reenrich_ip and ioc_type in ("ipv4", "ipv6")

    if not confirmed:
        return pending_confirmation({
            "action": "rescan_finding",
            "finding_id": finding_id,
            "title": title[:80],
            "reenrich_ip": will_reenrich_ip,
        })

    actions_taken = []
    if will_reenrich_ip and ioc_value:
        from ati_evn.enrichment_v2.ip_enricher import enrich_ip_full
        try:
            await enrich_ip_full(ioc_value, force=True)
            actions_taken.append("ip_reenriched")
        except Exception as e:
            actions_taken.append(f"ip_reenrich_failed:{str(e)[:80]}")

    now = datetime.now(timezone.utc)
    async with async_session() as session:
        fi = await session.get(Finding, finding_id)
        if not fi:
            return tool_error(f"Finding #{finding_id} not found")
        meta = dict(fi.metadata_ or {})
        history = meta.get("rescan_history") or []
        history.append({"at": now.isoformat(), "actions": actions_taken})
        meta["rescan_history"] = history[-20:]
        fi.metadata_ = meta
        await session.commit()

    return {
        "status": "rescanned",
        "finding_id": finding_id,
        "actions_taken": actions_taken,
    }
