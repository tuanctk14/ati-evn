"""Trigger urlscan.io brand abuse scan for keyword via agent -- non-destructive."""
from __future__ import annotations

import asyncio
import logging

from sqlalchemy import select

from ati_evn.agent.tools._action_base import register_action_tool
from ati_evn.agent.tools._base import tool_error
from ati_evn.db.models import Customer
from ati_evn.db.query_utils import customer_match_order_by, customer_name_or_code_match
from ati_evn.db.session import async_session
from ati_evn.external.brand_abuse_ingest import ingest_brand_abuse
from ati_evn.external.urlscan_client import UrlscanAPIError, UrlscanConfigError, search_brand

logger = logging.getLogger("ati_evn.agent.tools.scan_brand_abuse")

# asyncio.create_task() only holds a WEAK reference internally -- keep a
# strong reference here (same fix rescan.py applies to
# trigger_rescan_background) so a scan task can't be garbage-collected
# mid-run with no warning.
_background_tasks: set[asyncio.Task] = set()


async def _run_scan(keyword: str, primary_domain: str | None, max_results: int) -> dict:
    try:
        sightings = await search_brand(keyword, primary_domain, max_results=max_results)
    except UrlscanConfigError as e:
        return tool_error(f"Config: {e}")
    except UrlscanAPIError as e:
        return tool_error(f"API: {str(e)[:200]}")
    except Exception as e:
        return tool_error(f"Scan failed: {str(e)[:200]}")

    if not sightings:
        return {
            "keyword": keyword,
            "sightings_found": 0,
            "findings_created": 0,
            "note": "No sightings for this keyword.",
        }

    stats = await ingest_brand_abuse(sightings)
    return {
        "keyword": keyword,
        "primary_domain": primary_domain,
        "sightings_found": len(sightings),
        "sightings_new": stats.get("new", 0),
        "sightings_updated": stats.get("updated", 0),
        "typosquat_matched": stats.get("typosquat_matched", 0),
        "rule_matched": stats.get("rule_matched", 0),
        "llm_calls": stats.get("llm_calls", 0),
        "findings_created": stats.get("findings_created", 0),
        "queued_for_alert": stats.get("queued_for_alert", 0),
    }


def _format_scan_result(result: dict) -> str:
    if not result.get("success", True):
        return f"⚠️ Brand abuse scan lỗi ({result.get('keyword', '?')}): {result.get('error', '')[:200]}"
    if result.get("sightings_found", 0) == 0:
        return f"🎭 Brand abuse scan hoàn tất ({result['keyword']}): không tìm thấy sighting nào."
    return (
        f"🎭 Brand abuse scan hoàn tất ({result['keyword']}): "
        f"{result['sightings_found']} sighting ({result.get('sightings_new', 0)} mới, "
        f"{result.get('sightings_updated', 0)} cập nhật), "
        f"{result.get('findings_created', 0)} finding mới."
    )


async def _run_and_notify(
    keyword: str, primary_domain: str | None, max_results: int, bot, chat_id: int,
) -> dict:
    result = await _run_scan(keyword, primary_domain, max_results)
    try:
        await bot.send_message(chat_id, _format_scan_result(result))
    except Exception:  # noqa: BLE001 — notification best-effort, never crash the scan
        logger.exception("Failed to send scan-complete notification to chat %s", chat_id)
    return result


@register_action_tool(
    name="scan_brand_abuse",
    destructive=False,
    description=(
        "Scan urlscan.io for brand abuse (phishing, typosquat, impersonation) "
        "matching keyword. Optionally provide primary_domain for typosquat "
        "detection. Runs 3-stage pipeline: rule engine -> typosquat -> LLM. "
        "IMPORTANT: this call can take longer than the agent turn's own "
        "timeout budget (live external API + up to several LLM classifier "
        "calls). It runs in the background and returns immediately with "
        "status='queued' -- tell the analyst the scan has started and "
        "they'll get a follow-up Telegram message with results, do NOT "
        "wait for or claim scan results in this same turn."
    ),
    parameters={
        "type": "object",
        "properties": {
            "keyword": {"type": "string"},
            "primary_domain": {
                "type": "string",
                "description": "Domain for typosquat reference (e.g. evn.com.vn)",
            },
            "customer": {
                "type": "string",
                "description": "Resolve keyword + primary_domain from customer name/code",
            },
            "max_results": {"type": "integer", "default": 30, "description": "Cap results (1-100)"},
        },
        "required": [],
    },
)
async def scan_brand_abuse(
    keyword: str | None = None,
    primary_domain: str | None = None,
    customer: str | None = None,
    max_results: int = 30,
    _bot=None,
    _chat_id: int | None = None,
) -> dict:
    max_results = min(max(max_results, 1), 100)

    if customer and not keyword:
        async with async_session() as session:
            row = await session.execute(
                select(Customer).where(
                    customer_name_or_code_match(customer),
                    Customer.deleted_at.is_(None),
                ).order_by(customer_match_order_by(customer)).limit(1)
            )
            c = row.scalar_one_or_none()
            if not c:
                return tool_error(f"Customer '{customer}' not found")
            keyword = c.name
            primary_domain = primary_domain or c.primary_domain

    if not keyword:
        return tool_error("Must provide keyword or customer")

    if _bot is not None and _chat_id is not None:
        task = asyncio.create_task(
            _run_and_notify(keyword, primary_domain, max_results, _bot, _chat_id)
        )
        _background_tasks.add(task)
        task.add_done_callback(_background_tasks.discard)
        return {
            "status": "queued",
            "keyword": keyword,
            "primary_domain": primary_domain,
            "note": (
                "Scan is running in the background (can take 20-60s+). "
                "Analyst will receive a Telegram message with results when done."
            ),
        }

    # No bot/chat context (e.g. CLI test harness) -- run synchronously,
    # same behavior as before this tool supported background execution.
    return await _run_scan(keyword, primary_domain, max_results)
