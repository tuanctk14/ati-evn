"""/export_indicators [--type=T] [--customer=X] [--severity=S] [--since_days=N]

Exports ThreatIndicators to CSV, sent directly as a Telegram document
(same delivery pattern as /export findings|alerts|... in export.py).
"""
from __future__ import annotations

import csv
import io
import logging
from datetime import datetime, timedelta, timezone

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import BufferedInputFile, Message
from sqlalchemy import select

from ati_evn.db.models import Customer, ThreatIndicator
from ati_evn.db.query_utils import customer_name_or_code_match
from ati_evn.db.session import async_session
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command

router = Router()
logger = logging.getLogger("ati_evn.telegram.export_indicators")

CSV_BOM = "﻿"


@router.message(Command("export_indicators"))
@log_command("export_indicators")
async def cmd_export_indicators(message: Message):
    args = parse_args(message.text or "", "export_indicators")
    indicator_type = args.get("type")
    customer_arg = args.get("customer")
    severity = args.get("severity")
    try:
        since_days = int(args.get("since_days") or 30)
    except ValueError:
        since_days = 30

    cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)

    async with async_session() as session:
        stmt = select(ThreatIndicator).where(
            ThreatIndicator.first_seen >= cutoff,
        ).order_by(ThreatIndicator.first_seen.desc())

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

        customer_names: dict[int, str] = {}
        for ti in rows:
            if ti.customer_id and ti.customer_id not in customer_names:
                c = await session.get(Customer, ti.customer_id)
                customer_names[ti.customer_id] = c.name if c else f"#{ti.customer_id}"

    if not rows:
        await message.answer("📭 Không có threat indicator nào để export.")
        return

    buf = io.StringIO()
    buf.write(CSV_BOM)
    writer = csv.writer(buf)
    writer.writerow([
        "id", "indicator_type", "indicator_value", "severity", "customer",
        "status", "source", "title", "first_seen", "expires_at", "acknowledged",
    ])
    for ti in rows:
        sev = ti.severity.value if hasattr(ti.severity, "value") else str(ti.severity)
        writer.writerow([
            ti.id, ti.indicator_type, ti.indicator_value, sev,
            customer_names.get(ti.customer_id, ""), ti.status, ti.source,
            ti.title, ti.first_seen.isoformat() if ti.first_seen else "",
            ti.expires_at.isoformat() if ti.expires_at else "",
            "yes" if ti.acknowledged_at else "no",
        ])

    content = buf.getvalue().encode("utf-8")
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"indicators_{ts}.csv"
    f = BufferedInputFile(content, filename=filename)
    await message.answer_document(f, caption=f"Export indicators — {len(rows)} rows, {len(content)} bytes")
