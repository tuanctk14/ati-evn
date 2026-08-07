"""Wrap slice 4.7 get_rule_for_cve for Telegram. Falls back to an on-demand
single NVD fetch when the CVE has no data in the system yet (get_rule_for_cve
itself doesn't raise for an unknown CVE — it just falls through to
source=ai_generated with empty context — so we check DB presence up front
and only then decide whether to try enriching from NVD first)."""
from __future__ import annotations

import logging

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import BufferedInputFile, Message
from sqlalchemy import select

from ati_evn.db.models import Detection
from ati_evn.db.session import async_session
from ati_evn.fetchers.cve.nvd_single import fetch_single_cve
from ati_evn.rules.orchestrator import get_rule_for_cve
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command
from ati_evn.telegram.formatter.common import truncate

logger = logging.getLogger("ati_evn.telegram.rule")
router = Router()


async def _cve_known_to_system(cve_id: str) -> bool:
    async with async_session() as session:
        result = await session.execute(
            select(Detection.id).where(
                Detection.ioc_value == cve_id.lower(),
                Detection.source == "nvd",
            ).limit(1)
        )
        return result.scalar_one_or_none() is not None


@router.message(Command("rule"))
@log_command("rule")
async def cmd_rule(message: Message):
    args = parse_args(message.text or "", "rule")
    pos = args.get("_positional", [])
    if not pos:
        await message.answer("Cú pháp: /rule <CVE-ID> [--regen]")
        return
    cve_id = pos[0].upper()
    regen = bool(args.get("regen"))

    thinking = await message.answer(f"🔍 Đang tìm rule cho {cve_id}...")

    if not await _cve_known_to_system(cve_id):
        logger.info("%s not in system yet — trying NVD on-demand fetch", cve_id)
        fetched = await fetch_single_cve(cve_id)
        if not fetched:
            await thinking.delete()
            await message.answer(
                f"CVE {cve_id} không có trong hệ thống và NVD cũng "
                f"không trả kết quả. Kiểm tra ID."
            )
            return

    try:
        result = await get_rule_for_cve(cve_id, force_regen=regen)
    except Exception as e:
        await thinking.delete()
        logger.exception("get_rule_for_cve failed for %s: %s", cve_id, e)
        await message.answer(f"⚠️ Lỗi khi tìm rule: {str(e)[:200]}")
        return

    await thinking.delete()

    source = result.get("source", "unknown")
    p = result["primary_rule"]
    title = p.get("title", "?")
    yaml_text = p.get("yaml", "")
    conf = result.get("match_confidence", 0)

    header_emoji = {
        "community_direct": "✅",
        "community_behavioral": "⚠️",
        "ai_generated": "🤖",
    }.get(source, "•")

    header = f"{header_emoji} Rule cho {cve_id} — nguồn: {source}"
    if conf:
        header += f" (confidence {conf:.2f})"
    if source == "community_behavioral":
        header += (
            "\n⚠️ Behavioral match: rule không gắn CVE này nhưng cùng "
            "ATT&CK technique. Analyst nên review kỹ trước khi deploy."
        )

    title_line = f"\nTitle: {title}"
    source_ref = p.get("source_ref")
    source_ref_line = f"\nSource: {source_ref}" if source_ref else ""

    ai_meta = result.get("ai_metadata")
    ai_line = ""
    if ai_meta:
        ai_line = (
            f"\n\nAI Metadata:"
            f"\n  Model: {ai_meta.get('model')}"
            f"\n  Confidence: {ai_meta.get('confidence')}"
            f"\n  Analyst notes: {truncate(ai_meta.get('analyst_notes'), 400)}"
        )

    alts_line = ""
    alts = result.get("alternates", [])
    if alts:
        alt_titles = [
            f"  [{i + 1}] {truncate(a.get('title'), 70)} (score {a.get('score')})"
            for i, a in enumerate(alts[:4])
        ]
        alts_line = f"\n\n{len(alts)} alternate community rule(s):\n" + "\n".join(alt_titles)

    summary_msg = header + title_line + source_ref_line + ai_line + alts_line
    await message.answer(summary_msg, disable_web_page_preview=True)

    yaml_section = f"--- Sigma YAML ---\n\n{yaml_text}"
    if len(yaml_section) < 3500:
        await message.answer(f"```yaml\n{yaml_text}\n```", parse_mode="Markdown")
    else:
        f = BufferedInputFile(yaml_text.encode("utf-8"), filename=f"{cve_id}_sigma.yml")
        await message.answer_document(f, caption="Sigma YAML (file)")
