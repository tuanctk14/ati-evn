"""Search OTX pulses attached to IPs. Query IpEnrichment where
provider=otx and pulse data has matching family/tag/actor/malware.

Note: uses IpEnrichment.data JSON -- must load rows and filter in Python
(plain JSON column, not JSONB, so no SQL-level nested search).
"""
from __future__ import annotations

from sqlalchemy import select

from ati_evn.agent.tools._base import register_tool, tool_error
from ati_evn.db.models import IpEnrichment
from ati_evn.db.session import async_session


@register_tool(
    name="search_pulses",
    description=(
        "Search OTX pulses attached to enriched IPs. Filter pulses by "
        "malware family name, tag, adversary/actor name. Returns IPs "
        "with matching pulses. OTX-specific -- Pulsedive threats + other "
        "providers not covered."
    ),
    parameters={
        "type": "object",
        "properties": {
            "filter_by": {"type": "string", "enum": ["family", "tag", "adversary", "any"], "default": "any"},
            "value": {"type": "string", "description": "Search value (case-insensitive)"},
            "limit": {"type": "integer", "default": 20},
        },
        "required": ["value"],
    },
)
async def search_pulses(value: str, filter_by: str = "any", limit: int = 20) -> dict:
    value_lower = value.lower().strip()
    if not value_lower:
        return tool_error("value cannot be empty")
    limit = min(max(limit, 1), 50)

    async with async_session() as session:
        stmt = select(IpEnrichment).where(
            IpEnrichment.provider == "otx",
            IpEnrichment.error_message.is_(None),
        )
        all_otx = list((await session.execute(stmt)).scalars())

    matches = []
    for row in all_otx:
        data = row.data or {}
        pulses = data.get("pulses") or []
        for pulse in pulses:
            match = False
            if filter_by in ("family", "any"):
                families = [f.lower() for f in (pulse.get("malware_families") or []) if f]
                if any(value_lower in f for f in families):
                    match = True
            if not match and filter_by in ("tag", "any"):
                tags = [t.lower() for t in (pulse.get("tags") or []) if t]
                if any(value_lower in t for t in tags):
                    match = True
            if not match and filter_by in ("adversary", "any"):
                adversary = (pulse.get("adversary") or "").lower()
                if adversary and value_lower in adversary:
                    match = True

            if match:
                matches.append({
                    "ip": row.ip,
                    "pulse_name": pulse.get("name"),
                    "pulse_id": pulse.get("id"),
                    "author": pulse.get("author"),
                    "malware_families": pulse.get("malware_families"),
                    "tags": pulse.get("tags"),
                    "adversary": pulse.get("adversary"),
                    "created": pulse.get("created"),
                })
                if len(matches) >= limit:
                    break
        if len(matches) >= limit:
            break

    return {
        "search_value": value,
        "filter_by": filter_by,
        "total_matches": len(matches),
        "matches": matches[:limit],
    }
