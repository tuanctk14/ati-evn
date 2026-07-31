"""Trigger GrayHatWarfare scan for keyword via agent -- non-destructive."""
from __future__ import annotations

import asyncio
import logging

from ati_evn.agent.tools._action_base import register_action_tool
from ati_evn.agent.tools._base import tool_error
from ati_evn.external.document_ingest import ingest_documents
from ati_evn.external.grayhat_client import GrayhatAPIError, GrayhatConfigError, search_keyword

logger = logging.getLogger("ati_evn.agent.tools.scan_document_leak")

# asyncio.create_task() only holds a WEAK reference internally -- keep a
# strong reference here (same fix scan_brand_abuse.py / rescan.py apply)
# so a scan task can't be garbage-collected mid-run with no warning.
_background_tasks: set[asyncio.Task] = set()


async def _run_scan(keyword: str, max_files: int) -> dict:
    try:
        files = await search_keyword(keyword, max_files=max_files)
    except GrayhatConfigError as e:
        return tool_error(f"Config: {e}")
    except GrayhatAPIError as e:
        return tool_error(f"API: {str(e)[:200]}")
    except Exception as e:
        logger.warning("scan_document_leak failed for keyword=%r: %s", keyword, e)
        return tool_error(f"Scan failed: {str(e)[:200]}")

    if not files:
        return {
            "keyword": keyword,
            "files_found": 0,
            "documents_new": 0,
            "indicators_created": 0,
            "note": "No files matched keyword.",
        }

    stats = await ingest_documents(files)
    return {
        "keyword": keyword,
        "files_found": len(files),
        "documents_new": stats.get("new", 0),
        "documents_updated": stats.get("updated", 0),
        "whitelisted": stats.get("whitelisted", 0),
        "rule_matches": stats.get("rule_matched", 0),
        "llm_calls": stats.get("llm_calls", 0),
        "llm_relevant": stats.get("llm_relevant", 0),
        "indicators_created": stats.get("indicators_created", 0),
        "queued_for_alert": stats.get("queued_for_alert", 0),
    }


def _format_scan_result(result: dict) -> str:
    if not result.get("success", True):
        return f"📄 Document leak scan lỗi ({result.get('keyword', '?')}): {result.get('error', '')[:200]}"
    if result.get("files_found", 0) == 0:
        return f"📄 Document leak scan hoàn tất ({result['keyword']}): không tìm thấy file nào."
    return (
        f"📄 Document leak scan hoàn tất ({result['keyword']}): "
        f"{result['files_found']} file ({result.get('documents_new', 0)} mới, "
        f"{result.get('documents_updated', 0)} cập nhật), "
        f"{result.get('indicators_created', 0)} indicator mới."
    )


async def _run_and_notify(keyword: str, max_files: int, bot, chat_id: int) -> dict:
    result = await _run_scan(keyword, max_files)
    try:
        await bot.send_message(chat_id, _format_scan_result(result))
    except Exception:  # noqa: BLE001 — notification best-effort, never crash the scan
        logger.exception("Failed to send scan-complete notification to chat %s", chat_id)
    return result


@register_action_tool(
    name="scan_document_leak",
    destructive=False,
    description=(
        "Scan GrayHatWarfare for exposed documents matching keyword. "
        "Runs 3-stage pipeline: bucket whitelist -> rule engine -> LLM. "
        "Creates ExposedDocument entries + Findings if relevant. "
        "Free tier ~15% index coverage. "
        "IMPORTANT: this call can take longer than the agent turn's own "
        "timeout budget (live external API + up to several LLM classifier "
        "calls per file). It runs in the background and returns "
        "immediately with status='queued' -- tell the analyst the scan "
        "has started and they'll get a follow-up Telegram message with "
        "results, do NOT wait for or claim scan results in this same turn."
    ),
    parameters={
        "type": "object",
        "properties": {
            "keyword": {"type": "string", "description": "Search term (EVN, GENCO1, etc.)"},
            "max_files": {"type": "integer", "default": 50, "description": "Cap results (1-100)"},
        },
        "required": ["keyword"],
    },
)
async def scan_document_leak(
    keyword: str, max_files: int = 50,
    _bot=None, _chat_id: int | None = None,
) -> dict:
    max_files = min(max(max_files, 1), 100)

    if _bot is not None and _chat_id is not None:
        task = asyncio.create_task(_run_and_notify(keyword, max_files, _bot, _chat_id))
        _background_tasks.add(task)
        task.add_done_callback(_background_tasks.discard)
        return {
            "status": "queued",
            "keyword": keyword,
            "note": (
                "Scan is running in the background (can take 20-60s+). "
                "Analyst will receive a Telegram message with results when done."
            ),
        }

    # No bot/chat context (e.g. CLI test harness) -- run synchronously,
    # same behavior as before this tool supported background execution.
    return await _run_scan(keyword, max_files)
