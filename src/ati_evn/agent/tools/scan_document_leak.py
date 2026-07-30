"""Trigger GrayHatWarfare scan for keyword via agent -- non-destructive."""
from __future__ import annotations

from ati_evn.agent.tools._action_base import register_action_tool
from ati_evn.agent.tools._base import tool_error
from ati_evn.external.document_ingest import ingest_documents
from ati_evn.external.grayhat_client import GrayhatAPIError, GrayhatConfigError, search_keyword


@register_action_tool(
    name="scan_document_leak",
    destructive=False,
    description=(
        "Scan GrayHatWarfare for exposed documents matching keyword. "
        "Runs 3-stage pipeline: bucket whitelist -> rule engine -> LLM. "
        "Creates ExposedDocument entries + Findings if relevant. "
        "Free tier ~15% index coverage."
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
async def scan_document_leak(keyword: str, max_files: int = 50) -> dict:
    max_files = min(max(max_files, 1), 100)
    try:
        files = await search_keyword(keyword, max_files=max_files)
    except GrayhatConfigError as e:
        return tool_error(f"Config: {e}")
    except GrayhatAPIError as e:
        return tool_error(f"API: {str(e)[:200]}")
    except Exception as e:
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
