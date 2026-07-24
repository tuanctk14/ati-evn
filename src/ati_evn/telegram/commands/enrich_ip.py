"""/enrich_ip <ip> [--force] [--full] — multi-provider IP enrichment.

Fast path (default): foreground providers only (AbuseIPDB + VirusTotal).
--full: all 5 providers (+ OTX, Pulsedive, LeakIX), slower (~15-30s).
"""
from __future__ import annotations

import logging

from aiogram import Router
from aiogram.enums import ChatAction
from aiogram.filters import Command
from aiogram.types import Message
from sqlalchemy import select

from ati_evn.db.models import Finding
from ati_evn.db.session import async_session
from ati_evn.enrichment_v2.ip_enricher import enrich_ip_foreground, enrich_ip_full
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command

router = Router()
logger = logging.getLogger("ati_evn.telegram.enrich_ip")

_VERDICT_EMOJI = {"malicious": "🔴", "suspicious": "🟠", "benign": "🟢", "unknown": "⚪"}

_CONSENSUS_LABEL = {
    "disputed": "⚠ DISPUTED — providers disagree (some malicious, some benign)",
    "partial_consensus": "◐ PARTIAL — some disagreement in severity",
    "consensus": "✓ CONSENSUS — providers agree",
}


def _risk_band(score: float) -> str:
    if score >= 75:
        return "HIGH"
    if score >= 40:
        return "MODERATE"
    return "LOW"


@router.message(Command("enrich_ip"))
@log_command("enrich_ip")
async def cmd_enrich_ip(message: Message):
    args = parse_args(message.text or "", "enrich_ip")
    pos = args.get("_positional", [])
    force = bool(args.get("force"))
    full = bool(args.get("full"))
    if not pos:
        await message.answer(
            "Cú pháp: /enrich_ip <ip> [--force] [--full]\n"
            "  --force: bỏ cache TTL\n"
            "  --full: chờ đủ 5 provider (chậm 10-30s), mặc định 2 provider\n"
            "Ví dụ: /enrich_ip 45.146.164.110"
        )
        return

    ip = pos[0].strip()
    thinking = await message.answer(
        f"🔎 Enriching {ip} "
        + ("(full 5 provider, 10-30s)..." if full else "(fast 2 provider)...")
    )
    await message.bot.send_chat_action(message.chat.id, ChatAction.TYPING)

    try:
        if full:
            results, agg = await enrich_ip_full(ip, force=force)
        else:
            results, agg = await enrich_ip_foreground(ip, force=force)
    except Exception as e:
        await thinking.delete()
        logger.exception("Enrichment error")
        await message.answer(f"⚠️ Lỗi: {str(e)[:200]}")
        return

    await thinking.delete()

    if not agg:
        await message.answer(f"⚠️ Không tính được aggregate cho {ip}")
        return

    if agg.responded_provider_count == 0:
        status_emoji, status_label = "❓", "NO DATA"
    else:
        status_emoji, status_label = "✓", f"RISK {_risk_band(agg.aggregate_risk_score)}"

    consensus_line = _CONSENSUS_LABEL.get(agg.consensus_status, "? unknown")

    lines = [
        f"🔎 IP Enrichment — {ip}",
        "",
        f"{status_emoji} {status_label}",
        "",
        f"Risk: {agg.aggregate_risk_score:.1f}/100 ({_risk_band(agg.aggregate_risk_score)})",
        f"Max Provider Score: {agg.max_provider_score:.1f}",
        "",
        f"Consensus: {consensus_line}",
        f"  Positive (malicious): {agg.positive_provider_count}",
        f"  Supporting (malicious+suspicious): {agg.supporting_provider_count}",
        f"  Benign: {agg.responded_provider_count - agg.supporting_provider_count}",
        "",
        f"Coverage: {agg.responded_provider_count}/{agg.enabled_provider_count} "
        f"providers responded ({agg.coverage_score:.0%})",
    ]

    if agg.coverage_score < 1.0:
        missing = agg.enabled_provider_count - agg.responded_provider_count
        lines.append(f"⏳ {missing} provider(s) pending — score may change (dùng --full để chạy đủ)")

    lines.append("")
    lines.append("Per-provider verdicts:")
    for r in results:
        verdict = r.get("verdict") or "pending"
        score = r.get("score")
        score_str = f"{score:.0f}" if score is not None else "-"
        emoji = _VERDICT_EMOJI.get(verdict, "⚪")
        err = f" ({r['error'][:40]})" if r.get("error") else ""
        lines.append(f"  {emoji} {r['provider']:12s} {verdict:11s} score={score_str}{err}")

    async with async_session() as session:
        f_stmt = select(Finding).where(Finding.ioc_value == ip).limit(5)
        findings = list((await session.execute(f_stmt)).scalars())
        if findings:
            lines.append("")
            lines.append(f"Linked Findings ({len(findings)}):")
            for f in findings[:5]:
                sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                lines.append(f"  #{f.id} — {sev} — {f.title[:60]}")

    await message.answer("\n".join(lines))
