"""Route free-text messages to agent loop.

Flow:
1. Load or create session
2. Start background typing indicator
3. Run agent (function-calling -> ReAct fallback -> answer + trace)
4. Stop typing
5. Send answer (auto-split if >3500 chars)
6. Send trace as separate message
7. Log to command_log with command='__free_text__'
"""
from __future__ import annotations

import asyncio
import logging
import re
import time

from aiogram.enums import ChatAction
from aiogram.exceptions import TelegramBadRequest
from aiogram.types import Message

from ati_evn.agent.loop import run_agent
from ati_evn.agent.loop.legacy_finding_postfilter import postfilter_legacy_finding_actions
from ati_evn.agent.loop.postfilter import postfilter_answer, sanitize_telegram_markdown
from ati_evn.agent.session.state import load_or_create
from ati_evn.config import get_settings
from ati_evn.db.models import CommandLog
from ati_evn.db.session import async_session
from ati_evn.llm.client import LLMClient

logger = logging.getLogger("ati_evn.telegram.agent_handler")

ANSWER_MAX_CHARS = 3500


async def handle_free_text(message: Message) -> None:
    text = (message.text or "").strip()
    user_id = message.from_user.id
    username = message.from_user.username
    start = time.monotonic()
    status = "ok"
    error: str | None = None
    summary: str | None = None
    trace_block = ""

    # Let the analyst know the agent picked up the message — the typing
    # indicator alone is easy to miss over a run that can take 10-20s.
    thinking = await message.answer("🤖 Đang phân tích câu hỏi...")

    # Start background typing indicator
    typing_task = asyncio.create_task(
        _keep_typing(message.bot, message.chat.id)
    )

    try:
        settings = get_settings()
        client = LLMClient(settings)
        session = await load_or_create(user_id)
        session._bot = message.bot
        session._chat_id = message.chat.id

        answer, trace, trace_block = await run_agent(client, session, text)
        answer = sanitize_telegram_markdown(answer)
        answer, filter_stats = postfilter_answer(answer)
        answer, legacy_stats = await postfilter_legacy_finding_actions(answer)
        if filter_stats["replaced"] or filter_stats["stripped"]:
            fixes = ", ".join(f"{b}->{g}" for b, g in filter_stats["replaced"])
            trace_block = (trace_block or "") + f"\n  [postfilter fixed: {fixes}]"
        if legacy_stats["rewritten"]:
            fixes = ", ".join(f"{b}->/acknowledge_indicator {tid}" for b, tid in legacy_stats["rewritten"])
            trace_block = (trace_block or "") + f"\n  [legacy-finding postfilter: {fixes}]"
        summary = (
            f"agent {trace.method}, {len(trace.tool_calls)} tools, "
            f"{trace.total_prompt_tokens + trace.total_completion_tokens} tok"
        )

    except Exception as e:
        status = "error"
        error = str(e)[:500]
        logger.exception("Agent handler error: %s", e)
        answer = (
            f"⚠️ Xin lỗi, agent gặp lỗi: {str(e)[:200]}\n"
            f"Có thể thử dùng command trực tiếp thay thế."
        )
        trace_block = ""
    finally:
        typing_task.cancel()
        try:
            await typing_task
        except asyncio.CancelledError:
            pass
        try:
            await thinking.delete()
        except Exception:
            pass  # best-effort cleanup of the "thinking" placeholder -- message may already be gone

    # Send answer (auto-split if too long)
    for chunk in _split_answer(answer, ANSWER_MAX_CHARS):
        await _send_markdown(message, chunk)

    # Send trace as separate message
    if trace_block:
        await message.answer(trace_block, disable_web_page_preview=True)

    # Audit log
    elapsed_ms = int((time.monotonic() - start) * 1000)
    try:
        async with async_session() as session:
            entry = CommandLog(
                telegram_user_id=user_id,
                telegram_username=username,
                command="__free_text__",
                args={"text": text[:500]},
                result_status=status,
                result_summary=summary,
                error=error,
                latency_ms=elapsed_ms,
            )
            session.add(entry)
            await session.commit()
    except Exception as e:
        logger.warning("Failed to write command_log: %s", e)


async def _send_markdown(message: Message, chunk: str) -> None:
    """Send with Markdown rendering so **bold**/`code` from the LLM's
    answer actually renders instead of showing literal asterisks/backticks.
    Telegram's legacy Markdown mode throws BadRequest on unbalanced
    entities (common in free-form LLM output) — fall back to stripping
    the markup and sending plain text rather than losing the answer."""
    try:
        await message.answer(chunk, parse_mode="Markdown", disable_web_page_preview=True)
    except TelegramBadRequest:
        stripped = _strip_markdown(chunk).strip()
        if not stripped:
            # Telegram rejects an empty message outright (BadRequest:
            # "message text is empty") -- this crashed the whole turn
            # silently (no error shown to the analyst) when the agent's
            # answer was itself empty or pure markup punctuation.
            logger.warning(
                "Agent answer became empty after markdown strip; original: %r",
                chunk[:200],
            )
            stripped = "⚠️ (Câu trả lời rỗng sau khi xử lý — thử lại câu hỏi khác.)"
        await message.answer(stripped, disable_web_page_preview=True)


def _strip_markdown(text: str) -> str:
    """Remove common markdown markup so leftover literal ** / ``` don't
    clutter the plain-text fallback."""
    text = re.sub(r"```[a-zA-Z]*\n?", "", text)
    text = text.replace("```", "")
    text = re.sub(r"\*\*(.+?)\*\*", r"\1", text)
    text = re.sub(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)", r"\1", text)
    text = re.sub(r"`([^`]+)`", r"\1", text)
    return text


async def _keep_typing(bot, chat_id: int, interval: float = 4.0) -> None:
    """Send chat_action=typing every `interval` seconds until cancelled."""
    try:
        while True:
            try:
                await bot.send_chat_action(chat_id, ChatAction.TYPING)
            except Exception as e:
                logger.debug("send_chat_action failed: %s", e)
            await asyncio.sleep(interval)
    except asyncio.CancelledError:
        return


def _split_answer(text: str, max_chars: int) -> list[str]:
    """Split by sentence boundary if length exceeds max_chars.

    Prefer '. ' or '\\n\\n' as split points. Never split mid-word.
    If no reasonable split found, hard-cut at max_chars.
    """
    text = text.strip()
    if len(text) <= max_chars:
        return [text]

    parts: list[str] = []
    remaining = text
    while len(remaining) > max_chars:
        # Prefer paragraph break within budget
        cut = remaining.rfind("\n\n", 0, max_chars)
        if cut < max_chars // 2:
            # Fall back to sentence end
            cut = remaining.rfind(". ", 0, max_chars)
            if cut < max_chars // 2:
                cut = remaining.rfind(" ", 0, max_chars)
                if cut < 0:
                    cut = max_chars
            else:
                cut += 2  # include the "."
        parts.append(remaining[:cut].rstrip())
        remaining = remaining[cut:].lstrip()

    if remaining:
        parts.append(remaining)
    return parts
