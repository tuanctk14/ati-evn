"""Export commands.

Types:
  /export findings [--customer=X] [--since=7d] [--format=csv|json]
  /export alerts   [--customer=X] [--since=7d] [--format=csv|json]
  /export assets   [--customer=X]              [--format=csv]
  /export ioc_summary [--since=7d]              [--format=csv|json]
  /export weekly_report [--customer=X] [--since=7d]  [--format=md|pdf]

weekly_report uses LLM to generate an executive summary + concatenates
deterministic tables.

Output: uploaded to Telegram as file.
"""
from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime, timedelta, timezone

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import BufferedInputFile, Message
from sqlalchemy import func, select, text

from ati_evn.config import get_settings
from ati_evn.db.models import AlertQueue, Customer, CustomerAsset, Detection, Finding, FindingStatus
from ati_evn.db.query_utils import only_live_asset, only_live_customer, only_live_detection
from ati_evn.db.session import async_session
from ati_evn.llm.client import LLMClient
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command

logger = logging.getLogger("ati_evn.telegram.export")
router = Router()

CSV_BOM = "﻿"  # Excel-VN friendly UTF-8 BOM


def _parse_since(since_str: str) -> datetime:
    """Parse '7d', '24h', '30d' to a UTC datetime."""
    s = since_str.strip().lower()
    if s.endswith("d"):
        return datetime.now(timezone.utc) - timedelta(days=int(s[:-1]))
    if s.endswith("h"):
        return datetime.now(timezone.utc) - timedelta(hours=int(s[:-1]))
    raise ValueError(f"Invalid --since format: {since_str}")


def _rows_to_csv(rows: list[dict]) -> bytes:
    if not rows:
        return CSV_BOM.encode("utf-8")
    buf = io.StringIO()
    buf.write(CSV_BOM)
    writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue().encode("utf-8")


def _rows_to_json(rows: list[dict]) -> bytes:
    return json.dumps(rows, ensure_ascii=False, indent=2, default=str).encode("utf-8")


# ── findings ─────────────────────────────────────────────────────────────

async def _export_findings(since, customer_filter, format_, limit=None) -> tuple[bytes, str, str]:
    async with async_session() as session:
        stmt = select(Finding, Customer.name).join(
            Customer, Customer.id == Finding.customer_id,
        ).where(only_live_customer())
        if since:
            stmt = stmt.where(Finding.first_seen >= since)
        if customer_filter:
            stmt = stmt.where(Customer.name.ilike(f"%{customer_filter}%"))
        stmt = stmt.order_by(Finding.first_seen.desc())
        if limit:
            stmt = stmt.limit(limit)
        rows = (await session.execute(stmt)).all()

    data = [
        {
            "id": f.id, "customer": name, "ioc_type": f.ioc_type, "ioc_value": f.ioc_value,
            "title": f.title, "severity": f.severity.value, "status": f.status.value,
            "correlation_type": f.correlation_type, "source_count": f.source_count,
            "sources": ",".join(f.sources or []), "first_seen": f.first_seen.isoformat(),
            "last_seen": f.last_seen.isoformat(),
        }
        for f, name in rows
    ]
    filename = f"findings.{format_}"
    if format_ == "json":
        return _rows_to_json(data), filename, "application/json"
    return _rows_to_csv(data), filename, "text/csv"


# ── alerts ───────────────────────────────────────────────────────────────

async def _export_alerts(since, customer_filter, format_, limit=None) -> tuple[bytes, str, str]:
    async with async_session() as session:
        stmt = select(AlertQueue, Customer.name).join(
            Customer, Customer.id == AlertQueue.customer_id,
        ).where(only_live_customer())
        if since:
            stmt = stmt.where(AlertQueue.created_at >= since)
        if customer_filter:
            stmt = stmt.where(Customer.name.ilike(f"%{customer_filter}%"))
        stmt = stmt.order_by(AlertQueue.created_at.desc())
        if limit:
            stmt = stmt.limit(limit)
        rows = (await session.execute(stmt)).all()

    data = [
        {
            "id": a.id, "customer": name, "finding_id": a.finding_id, "state": a.state,
            "dispatch_reason": a.dispatch_reason, "attempt_count": a.attempt_count,
            "created_at": a.created_at.isoformat(),
            "dispatched_at": a.dispatched_at.isoformat() if a.dispatched_at else "",
        }
        for a, name in rows
    ]
    filename = f"alerts.{format_}"
    if format_ == "json":
        return _rows_to_json(data), filename, "application/json"
    return _rows_to_csv(data), filename, "text/csv"


# ── assets ───────────────────────────────────────────────────────────────

async def _export_assets(customer_filter, format_) -> tuple[bytes, str, str]:
    async with async_session() as session:
        stmt = select(CustomerAsset, Customer.name).join(
            Customer, Customer.id == CustomerAsset.customer_id,
        ).where(only_live_asset(), only_live_customer())
        if customer_filter:
            stmt = stmt.where(Customer.name.ilike(f"%{customer_filter}%"))
        rows = (await session.execute(stmt)).all()

    data = [
        {
            "id": a.id, "customer": name, "asset_type": a.asset_type.value, "asset_value": a.asset_value,
            "vendor": a.vendor or "", "product": a.product or "", "version": a.version or "",
            "criticality": a.criticality, "is_ics": a.is_ics, "is_internet_facing": a.is_internet_facing,
            "network_segment": a.network_segment.value if a.network_segment else "",
        }
        for a, name in rows
    ]
    return _rows_to_csv(data), "assets.csv", "text/csv"


# ── ioc_summary ──────────────────────────────────────────────────────────

async def _export_ioc_summary(since, format_) -> tuple[bytes, str, str]:
    async with async_session() as session:
        stmt = select(
            Detection.source, Detection.ioc_type, func.count().label("n"),
        ).where(only_live_detection()).group_by(Detection.source, Detection.ioc_type)
        if since:
            stmt = stmt.where(Detection.created_at >= since)
        stmt = stmt.order_by(func.count().desc())
        rows = (await session.execute(stmt)).all()

    data = [{"source": s, "ioc_type": t, "count": n} for s, t, n in rows]
    filename = f"ioc_summary.{format_}"
    if format_ == "json":
        return _rows_to_json(data), filename, "application/json"
    return _rows_to_csv(data), filename, "text/csv"


# ── weekly_report ────────────────────────────────────────────────────────

WEEKLY_REPORT_SYSTEM = """You are a CTI analyst writing an executive summary
for a Vietnamese electric utility SOC's weekly threat report. Given
aggregated security metrics, write a 300-500 word executive summary in
Vietnamese (keep technical terms like CVE-ID, ATT&CK, CVSS in English).

Output JSON with key: summary (the markdown text).

Cover: overall risk trend, most notable findings, top attacked customers,
recommended priorities for next week. Do NOT hallucinate any numbers not
provided in the input — use exactly the figures given.

Return ONLY the JSON, no markdown fences."""


async def _collect_weekly_data(since, customer_filter) -> dict:
    async with async_session() as session:
        stmt = select(Finding, Customer.name).join(
            Customer, Customer.id == Finding.customer_id,
        ).where(only_live_customer())
        if since:
            stmt = stmt.where(Finding.first_seen >= since)
        if customer_filter:
            stmt = stmt.where(Customer.name.ilike(f"%{customer_filter}%"))
        findings = (await session.execute(stmt)).all()

        sev_counts: dict[str, int] = {}
        for f, _ in findings:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

        top_cve = sorted(
            (f for f, _ in findings if f.ioc_type == "cve_id"),
            key=lambda f: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(f.severity.value, 9),
        )[:10]
        top_ioc = [f for f, _ in findings if f.ioc_type != "cve_id"][:5]

        customer_counts: dict[str, int] = {}
        for f, name in findings:
            if f.status == FindingStatus.OPEN:
                customer_counts[name] = customer_counts.get(name, 0) + 1
        top_customers = sorted(customer_counts.items(), key=lambda x: -x[1])[:5]

        top_tech_rows = await session.execute(text("""
            SELECT t->>'id' AS tech_id, count(*) AS n
            FROM findings f, jsonb_array_elements((f.metadata::jsonb->'attack_context'->'techniques')) AS t
            WHERE f.first_seen >= :cutoff
            GROUP BY t->>'id' ORDER BY n DESC LIMIT 5
        """), {"cutoff": since or (datetime.now(timezone.utc) - timedelta(days=7))})
        top_techniques = [(r[0], r[1]) for r in top_tech_rows.all()]

        dispatch_stmt = select(AlertQueue.state, func.count())
        if since:
            dispatch_stmt = dispatch_stmt.where(AlertQueue.created_at >= since)
        dispatch_stmt = dispatch_stmt.group_by(AlertQueue.state)
        dispatch_stats = dict((await session.execute(dispatch_stmt)).all())

    return {
        "sev_counts": sev_counts,
        "top_cve": top_cve,
        "top_ioc": top_ioc,
        "top_customers": top_customers,
        "top_techniques": top_techniques,
        "dispatch_stats": dispatch_stats,
        "total_findings": len(findings),
    }


def _weekly_report_tables_md(data: dict) -> str:
    lines = ["## Số liệu chi tiết", ""]
    lines.append(f"**Tổng findings**: {data['total_findings']}")
    lines.append("")
    lines.append("### Theo severity")
    for sev, n in sorted(data["sev_counts"].items(), key=lambda x: -x[1]):
        lines.append(f"- {sev}: {n}")
    lines.append("")
    lines.append("### Top 10 CVE findings")
    for f in data["top_cve"]:
        lines.append(f"- #{f.id} [{f.severity.value}] {f.ioc_value} — {f.title[:80]}")
    lines.append("")
    lines.append("### Top 5 IOC findings")
    for f in data["top_ioc"]:
        lines.append(f"- #{f.id} [{f.severity.value}] {f.ioc_type}:{f.ioc_value[:50]}")
    lines.append("")
    lines.append("### Top 5 customer theo open findings")
    for name, n in data["top_customers"]:
        lines.append(f"- {name}: {n}")
    lines.append("")
    lines.append("### Top 5 ATT&CK techniques")
    for tech_id, n in data["top_techniques"]:
        lines.append(f"- {tech_id}: {n} lần")
    lines.append("")
    lines.append("### Alert dispatch stats")
    for state, n in data["dispatch_stats"].items():
        lines.append(f"- {state}: {n}")
    return "\n".join(lines)


def _md_to_pdf_bytes(markdown_text: str) -> bytes | None:
    """Very simple markdown -> PDF: paragraphs only, no nested markdown
    rendering. Returns None if reportlab isn't installed."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
    except ImportError:
        return None

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []
    for line in markdown_text.split("\n"):
        stripped = line.strip()
        if not stripped:
            story.append(Spacer(1, 8))
            continue
        style = styles["Heading2"] if stripped.startswith("#") else styles["Normal"]
        text_line = stripped.lstrip("#").strip()
        # reportlab Paragraph interprets '&' etc. as XML — escape minimally.
        text_line = text_line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        story.append(Paragraph(text_line, style))
    doc.build(story)
    return buf.getvalue()


async def _export_weekly_report(since, customer_filter, format_) -> tuple[bytes, str, str]:
    data = await _collect_weekly_data(since, customer_filter)
    tables_md = _weekly_report_tables_md(data)

    settings = get_settings()
    summary_md = "(LLM không cấu hình — bỏ qua executive summary)"
    if settings.openai_api_key:
        client = LLMClient(settings)
        try:
            raw = await client.chat_json(
                system=WEEKLY_REPORT_SYSTEM,
                user=json.dumps({
                    "total_findings": data["total_findings"],
                    "severity_breakdown": data["sev_counts"],
                    "top_customers": data["top_customers"],
                    "top_techniques": data["top_techniques"],
                    "dispatch_stats": data["dispatch_stats"],
                }, ensure_ascii=False),
                max_tokens=2048, temperature=0.3,
            )
            summary_md = raw.get("summary", summary_md)
        except Exception as e:
            logger.warning("Weekly report LLM summary failed: %s", e)
            summary_md = f"(LLM summary lỗi: {str(e)[:150]})"

    full_md = f"# Weekly Threat Report — ATI-EVN\n\n## Executive Summary\n\n{summary_md}\n\n{tables_md}"

    if format_ == "pdf":
        pdf_bytes = _md_to_pdf_bytes(full_md)
        if pdf_bytes is not None:
            return pdf_bytes, "weekly_report.pdf", "application/pdf"
        logger.warning("reportlab not available — degrading weekly_report to markdown")
        format_ = "md"

    return full_md.encode("utf-8"), "weekly_report.md", "text/markdown"


@router.message(Command("export"))
@log_command("export")
async def cmd_export(message: Message):
    args = parse_args(message.text or "", "export")
    pos = args.get("_positional", [])
    if not pos:
        await message.answer(
            "Cú pháp: /export <type> [flags]\n\n"
            "Types: findings | alerts | assets | ioc_summary | weekly_report\n"
            "Flags: --customer=X --since=7d --format=csv|json|md|pdf --limit=N"
        )
        return
    export_type = pos[0].lower()

    since = None
    if args.get("since"):
        try:
            since = _parse_since(args["since"])
        except ValueError as e:
            await message.answer(str(e))
            return

    customer_filter = args.get("customer")
    format_ = (args.get("format") or "csv").lower()

    limit = None
    if args.get("limit"):
        try:
            limit = int(args["limit"])
        except ValueError:
            await message.answer(f"--limit không hợp lệ: {args['limit']}")
            return

    thinking = await message.answer(f"📤 Đang tạo export {export_type}...")

    try:
        if export_type == "findings":
            content, filename, _mime = await _export_findings(since, customer_filter, format_, limit)
        elif export_type == "alerts":
            content, filename, _mime = await _export_alerts(since, customer_filter, format_, limit)
        elif export_type == "assets":
            content, filename, _mime = await _export_assets(customer_filter, format_)
        elif export_type == "ioc_summary":
            content, filename, _mime = await _export_ioc_summary(since, format_)
        elif export_type == "weekly_report":
            format_ = format_ if format_ in ("md", "pdf") else "md"
            content, filename, _mime = await _export_weekly_report(since, customer_filter, format_)
        else:
            await thinking.delete()
            await message.answer(f"Type không hỗ trợ: {export_type}")
            return
    except Exception as e:
        await thinking.delete()
        logger.exception("Export failed: %s", e)
        await message.answer(f"⚠️ Export lỗi: {str(e)[:200]}")
        return

    await thinking.delete()
    f = BufferedInputFile(content, filename=filename)
    await message.answer_document(f, caption=f"Export {export_type} — {len(content)} bytes")
