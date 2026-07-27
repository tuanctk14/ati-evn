"""Start threat intel article ingestion pipeline via agent.

There is no standalone start_ingestion_session() helper -- this
replicates the same inline flow as the /ingest command (fetch -> LLM
extract -> persist IngestionSession as pending). PDF ingestion needs a
Telegram Bot instance to download the file, which this tool doesn't
have access to -- only source_type in {url, text} is supported here;
PDF ingestion still requires the /ingest command directly.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ati_evn.agent.tools._action_base import pending_confirmation, register_action_tool
from ati_evn.agent.tools._base import tool_error
from ati_evn.db.models import IngestionSession
from ati_evn.db.session import async_session
from ati_evn.ingestion.extractor import extract_from_text
from ati_evn.ingestion.fetcher import fetch_url


@register_action_tool(
    name="ingest_article",
    destructive=True,
    description=(
        "Start threat intel article ingestion pipeline for a URL or raw "
        "text (PDF not supported here -- use /ingest for PDFs). Fetches "
        "content, extracts IOCs via LLM, creates an IngestionSession for "
        "analyst review. Analyst then confirms/rejects via /confirm_ingest "
        "or /reject_ingest."
    ),
    parameters={
        "type": "object",
        "properties": {
            "source": {"type": "string", "description": "URL, or raw text content"},
            "source_type": {"type": "string", "enum": ["url", "text"], "default": "url"},
        },
        "required": ["source"],
    },
)
async def ingest_article(
    source: str, source_type: str = "url", confirmed: bool = False,
    _session_id: str | int | None = None,
) -> dict:
    if not confirmed:
        return pending_confirmation({
            "action": "ingest_article",
            "source_type": source_type,
            "source": source[:200],
            "note": "Will fetch + LLM-extract IOCs. Creates an "
                    "IngestionSession pending analyst review.",
        })

    try:
        if source_type == "url":
            content = await fetch_url(source)
        elif source_type == "text":
            content = source
        else:
            return tool_error(f"Unsupported source_type: {source_type}")
    except Exception as e:
        return tool_error(f"Fetch failed: {str(e)[:200]}")

    if not content or len(content) < 100:
        return tool_error(f"Content too short ({len(content or '')} chars) to extract from.")

    try:
        extracted, model = await extract_from_text(content)
    except Exception as e:
        return tool_error(f"LLM extraction failed: {str(e)[:200]}")

    if "_error" in extracted:
        return tool_error(f"Extraction failed: {extracted['_error']}")

    try:
        telegram_user_id = int(_session_id) if _session_id is not None else 0
    except (TypeError, ValueError):
        telegram_user_id = 0

    async with async_session() as session:
        ingest = IngestionSession(
            telegram_user_id=telegram_user_id,
            telegram_username="agent",
            source_type=source_type,
            source_url=source if source_type == "url" else None,
            source_text=content[:8000] if source_type == "text" else None,
            extracted_data=extracted,
            extraction_model=model,
            status="pending",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )
        session.add(ingest)
        await session.commit()
        ingest_id = ingest.id

    return {
        "status": "ingestion_started",
        "session_id": ingest_id,
        "extracted_summary": {
            k: v for k, v in extracted.items()
            if k in ("iocs", "cves", "malware_families", "techniques")
        },
        "next_step": (
            f"Analyst reviews via /list_ingests, then /confirm_ingest {ingest_id} "
            f"or /reject_ingest {ingest_id}."
        ),
    }
