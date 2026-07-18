"""/ingest command — accepts URL, text, or PDF attachment.

Usage:
  /ingest https://example.com/article
  /ingest <paste text after command>
  (attach PDF with caption /ingest)
  (reply /ingest to a message with a PDF attachment)

Response: extraction preview with session ID + confirm/reject hints.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from aiogram import Router
from aiogram.enums import ChatAction
from aiogram.filters import Command
from aiogram.types import Message

from ati_evn.db.models import IngestionSession
from ati_evn.db.session import async_session
from ati_evn.ingestion.extractor import extract_from_text
from ati_evn.ingestion.fetcher import fetch_from_telegram_pdf, fetch_url
from ati_evn.telegram.audit import log_command
from ati_evn.telegram.formatter.ingestion import format_preview

logger = logging.getLogger("ati_evn.telegram.ingest")
router = Router()


def _looks_like_url(s: str) -> bool:
    return s.strip().startswith(("http://", "https://"))


@router.message(Command("ingest"))
@log_command("ingest")
async def cmd_ingest(message: Message):
    text = (message.text or message.caption or "").strip()
    parts = text.split(maxsplit=1)
    payload = parts[1].strip() if len(parts) > 1 else ""

    pdf_file_id: str | None = None
    if not payload:
        if message.reply_to_message and message.reply_to_message.document:
            doc = message.reply_to_message.document
            if doc.mime_type == "application/pdf":
                pdf_file_id = doc.file_id
    if not pdf_file_id and message.document:
        if message.document.mime_type == "application/pdf":
            pdf_file_id = message.document.file_id

    if not payload and not pdf_file_id:
        await message.answer(
            "Cú pháp:\n"
            "  /ingest https://example.com/article — fetch URL\n"
            "  /ingest <paste văn bản> — extract từ text\n"
            "  Attach PDF với caption /ingest — extract từ PDF\n"
            "  Reply /ingest tới message có PDF — extract từ PDF đó"
        )
        return

    source_type: str
    source_url: str | None = None
    source_text: str | None = None
    source_filename: str | None = None

    thinking = await message.answer("📥 Đang tải + phân tích...")
    await message.bot.send_chat_action(message.chat.id, ChatAction.TYPING)

    try:
        if pdf_file_id:
            source_type = "pdf"
            content, source_filename = await fetch_from_telegram_pdf(
                message.bot, pdf_file_id
            )
        elif _looks_like_url(payload):
            source_type = "url"
            source_url = payload
            content = await fetch_url(payload)
        else:
            source_type = "text"
            source_text = payload
            content = payload
    except Exception as e:
        await thinking.delete()
        logger.exception("Ingest fetch error: %s", e)
        await message.answer(
            f"⚠️ Không tải/đọc được nguồn: {str(e)[:200]}\n"
            f"Kiểm tra URL hợp lệ, PDF không encrypt, hoặc gõ text trực tiếp."
        )
        return

    if not content or len(content) < 100:
        await thinking.delete()
        await message.answer(
            f"⚠️ Nội dung quá ngắn ({len(content)} ký tự). "
            f"Kiểm tra nguồn có văn bản đáng kể không."
        )
        return

    try:
        extracted, model = await extract_from_text(content)
    except Exception as e:
        await thinking.delete()
        logger.exception("Extractor error: %s", e)
        await message.answer(f"⚠️ LLM extraction lỗi: {str(e)[:200]}")
        return

    await thinking.delete()

    if "_error" in extracted:
        await message.answer(f"⚠️ Extraction failed: {extracted['_error']}")
        return

    who = message.from_user.username or str(message.from_user.id)
    async with async_session() as session:
        ingest = IngestionSession(
            telegram_user_id=message.from_user.id,
            telegram_username=who,
            source_type=source_type,
            source_url=source_url,
            source_text=(source_text or content)[:8000] if source_type == "text" else None,
            source_filename=source_filename,
            extracted_data=extracted,
            extraction_model=model,
            status="pending",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )
        session.add(ingest)
        await session.commit()
        ingest_id = ingest.id

    preview = format_preview(
        ingest_id, source_type, source_url, source_filename, extracted
    )
    if len(preview) > 3800:
        parts_ = preview.split("\n\n")
        buf = ""
        for p in parts_:
            if len(buf) + len(p) + 2 > 3800:
                await message.answer(buf, disable_web_page_preview=True)
                buf = p
            else:
                buf = (buf + "\n\n" + p) if buf else p
        if buf:
            await message.answer(buf, disable_web_page_preview=True)
    else:
        await message.answer(preview, disable_web_page_preview=True)
