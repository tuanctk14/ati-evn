"""Trigger immediate fetch for a specific feed via agent -- non-destructive.

Note: run_feed_once() computes its own fetch window from FeedRunHistory
(last successful run) -- there is no since_hours override; the window
is not caller-controlled.
"""
from __future__ import annotations

from ati_evn.agent.tools._action_base import register_action_tool
from ati_evn.agent.tools._base import tool_error
from ati_evn.fetchers.scheduler import run_feed_once

VALID_FEEDS = ["nvd", "threatfox", "malwarebazaar", "urlhaus", "feodo"]


@register_action_tool(
    name="force_fetch_feed",
    destructive=False,
    description=(
        "Force immediate fetch of a threat intel feed (nvd/threatfox/"
        "malwarebazaar/urlhaus/feodo). Useful after a gap in scheduled "
        "runs. Fetch window is computed automatically from the last "
        "successful run, not caller-controlled. Returns fetch statistics."
    ),
    parameters={
        "type": "object",
        "properties": {
            "feed_name": {"type": "string", "enum": VALID_FEEDS},
        },
        "required": ["feed_name"],
    },
)
async def force_fetch_feed(feed_name: str) -> dict:
    if feed_name not in VALID_FEEDS:
        return tool_error(f"Unknown feed: {feed_name}. Valid: {', '.join(VALID_FEEDS)}")

    try:
        result = await run_feed_once(feed_name, trigger_reason="manual_force_fetch")
    except Exception as e:
        return tool_error(f"Fetch failed: {str(e)[:200]}")

    if result.get("status") != "success":
        return tool_error(
            f"Fetch {result.get('status', 'failed')}: {result.get('error', 'unknown error')}"
        )

    return {
        "feed_name": feed_name,
        "records_added": result.get("added", 0),
        "records_updated": result.get("updated", 0),
        "status": result.get("status"),
    }
