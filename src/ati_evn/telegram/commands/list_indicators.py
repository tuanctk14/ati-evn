"""/list_indicators [--type=T] [--customer=X] [--severity=S] [--status=active] [--limit=N]"""
from __future__ import annotations

import logging

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message
from sqlalchemy import desc, select

from ati_evn.db.models import Customer, ThreatIndicator
from ati_evn.db.query_utils import customer_name_or_code_match
from ati_evn.db.session import async_session
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command
from ati_evn.telegram.formatter.common import fmt_dt

router = Router()
logger = logging.getLogger("ati_evn.telegram.list_indicators")

BADGE = {
    "brand_abuse": "🎭", "exposed_document": "📄",
    "exposure": "📡", "ipv4": "🔎", "ipv6": "🔎",
    "domain": "🔎", "url": "🔎",
    "sha256": "🔎", "sha1": "🔎", "md5": "🔎",
}


@router.message(Command("list_indicators"))
@log_command("list_indicators")
async def cmd_list_indicators(message: Message):
    args = parse_args(message.text or "", "list_indicators")
    indicator_type = args.get("type")
    customer_arg = args.get("customer")
    severity = args.get("severity")
    status = (args.get("status") or "active").lower()
    try:
        limit = min(max(int(args.get("limit") or 20), 1), 50)
    except ValueError:
        limit = 20

    async with async_session() as session:
        stmt = select(ThreatIndicator).where(
            ThreatIndicator.status == status,
        ).order_by(desc(ThreatIndicator.first_seen)).limit(limit)

        if indicator_type:
            stmt = stmt.where(ThreatIndicator.indicator_type == indicator_type)
        if severity:
            stmt = stmt.where(ThreatIndicator.severity == severity.upper())

        if customer_arg:
            cr = await session.execute(
                select(Customer.id).where(customer_name_or_code_match(customer_arg)).limit(1)
            )
            cid = cr.scalar_one_or_none()
            if not cid:
                await message.answer(f"⚠️ Customer '{customer_arg}' không tìm thấy.")
                return
            stmt = stmt.where(ThreatIndicator.customer_id == cid)

        rows = list((await session.execute(stmt)).scalars())

        if not rows:
            await message.answer("📭 Không có threat indicator phù hợp filter.")
            return

        customer_names: dict[int, str] = {}
        for ti in rows:
            if ti.customer_id and ti.customer_id not in customer_names:
                c = await session.get(Customer, ti.customer_id)
                customer_names[ti.customer_id] = (c.short_code or c.name) if c else f"#{ti.customer_id}"

    lines = [f"📋 Threat Indicators (status={status}, limit {limit}):", ""]
    for ti in rows:
        badge = BADGE.get(ti.indicator_type, "⚠️")
        sev = ti.severity.value if hasattr(ti.severity, "value") else str(ti.severity)
        cust = customer_names.get(ti.customer_id, f"#{ti.customer_id}")
        first_seen = fmt_dt(ti.first_seen) if ti.first_seen else "?"
        ack_flag = " ✓ACK" if ti.acknowledged_at else ""
        lines.append(
            f"{badge} #{ti.id}  [{sev}]  {cust}  "
            f"{ti.indicator_type}  {ti.title[:50]}  "
            f"{first_seen}{ack_flag}"
        )

    lines.append("")
    lines.append("Dùng /indicator <id> để xem chi tiết.")
    await message.answer("\n".join(lines), disable_web_page_preview=True)
