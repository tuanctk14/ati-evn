"""Trigger Censys exposure scan for a single IP via agent -- non-destructive.

Note: upsert_exposures only writes to the Exposure table -- there is no
exposure-to-Finding rule engine yet (see external/exposure_ingest.py
docstring), so this tool does NOT create Findings, unlike the other scan
tools.
"""
from __future__ import annotations

from ati_evn.agent.tools._action_base import register_action_tool
from ati_evn.agent.tools._base import tool_error
from ati_evn.external.censys_client import CensysConfigError, CensysQuotaExceeded, search_ip
from ati_evn.external.exposure_ingest import upsert_exposures


@register_action_tool(
    name="scan_censys",
    destructive=False,
    description=(
        "Scan single IP via Censys Platform API. Returns exposed services "
        "and upserts Exposure entries (attributed to a customer asset if "
        "matched). Does NOT create Findings -- exposure-to-finding rules "
        "are not wired up yet. Free tier: 100 credits/month, single-IP only."
    ),
    parameters={
        "type": "object",
        "properties": {
            "ip": {"type": "string"},
        },
        "required": ["ip"],
    },
)
async def scan_censys(ip: str) -> dict:
    try:
        exposures = await search_ip(ip)
    except CensysConfigError as e:
        return tool_error(f"Config: {e}")
    except CensysQuotaExceeded as e:
        return tool_error(f"Quota exceeded: {str(e)[:200]}")
    except ValueError as e:
        return tool_error(f"Invalid IP: {e}")
    except Exception as e:
        return tool_error(f"Scan failed: {str(e)[:200]}")

    if not exposures:
        return {
            "ip": ip,
            "services_found": 0,
            "note": "No exposed services found for this IP.",
        }

    stats = await upsert_exposures(exposures)
    return {
        "ip": ip,
        "services_found": len(exposures),
        "exposures_new": stats.get("new", 0),
        "exposures_updated": stats.get("updated", 0),
        "attributed_to_asset": stats.get("attributed", 0),
        "orphan": stats.get("orphan", 0),
    }
