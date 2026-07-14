"""State transition commands. All require finding_id or alert_id."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message
from sqlalchemy import select

from ati_evn.db.models import AlertQueue, CustomerAsset, Finding, FindingStatus, FpMemory
from ati_evn.db.session import async_session
from ati_evn.match.fp_check import compute_fp_hash
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command

logger = logging.getLogger("ati_evn.telegram.action")
router = Router()


# ── /ack <alert_id> [--note=X] ──────────────────────────────────────────────

@router.message(Command("ack"))
@log_command("ack")
async def cmd_ack(message: Message):
    args = parse_args(message.text or "", "ack")
    pos = args.get("_positional", [])
    if not pos:
        await message.answer("Cú pháp: /ack <alert_id> [--note=X]")
        return
    try:
        alert_id = int(pos[0])
    except ValueError:
        await message.answer(f"alert_id không hợp lệ: {pos[0]}")
        return
    note = args.get("note")
    who = message.from_user.username or str(message.from_user.id)

    async with async_session() as session:
        alert = await session.get(AlertQueue, alert_id)
        if not alert:
            await message.answer(f"Không tìm thấy Alert #{alert_id}")
            return
        alert.state = "acknowledged"
        await session.commit()
    await message.answer(
        f"✅ Alert #{alert_id} acknowledged bởi @{who}"
        + (f"\nNote: {note}" if note else "")
    )


# ── /close <finding_id> --reason=X ──────────────────────────────────────────

@router.message(Command("close"))
@log_command("close")
async def cmd_close(message: Message):
    args = parse_args(message.text or "", "close")
    pos = args.get("_positional", [])
    reason = args.get("reason")
    if not pos or not reason:
        await message.answer("Cú pháp: /close <finding_id> --reason=X")
        return
    try:
        finding_id = int(pos[0])
    except ValueError:
        await message.answer(f"finding_id không hợp lệ: {pos[0]}")
        return
    who = message.from_user.username or str(message.from_user.id)

    async with async_session() as session:
        finding = await session.get(Finding, finding_id)
        if not finding:
            await message.answer(f"Không tìm thấy Finding #{finding_id}")
            return
        if finding.status == FindingStatus.CLOSED:
            await message.answer(f"Finding #{finding_id} đã closed từ trước.")
            return
        finding.status = FindingStatus.CLOSED
        finding.closed_at = datetime.now(timezone.utc)
        finding.closed_by = who
        finding.closed_reason = reason
        await session.commit()
    await message.answer(f"✅ Finding #{finding_id} closed bởi @{who}\nReason: {reason}")


# ── /mark_fp <finding_id> [--all-assets] [--reason=X] ───────────────────────

@router.message(Command("mark_fp"))
@log_command("mark_fp")
async def cmd_mark_fp(message: Message):
    args = parse_args(message.text or "", "mark_fp")
    pos = args.get("_positional", [])
    if not pos:
        await message.answer("Cú pháp: /mark_fp <finding_id> [--all-assets] [--reason=X]")
        return
    try:
        finding_id = int(pos[0])
    except ValueError:
        await message.answer(f"finding_id không hợp lệ: {pos[0]}")
        return
    all_assets = bool(args.get("all-assets"))
    reason = args.get("reason") or "marked FP via Telegram"
    who = message.from_user.username or str(message.from_user.id)

    async with async_session() as session:
        finding = await session.get(Finding, finding_id)
        if not finding:
            await message.answer(f"Không tìm thấy Finding #{finding_id}")
            return

        # Narrow scope by default: resolve the actual asset_id from
        # matched_asset (same lookup pattern as query.py's /finding and
        # /asset commands) so the FP rule only suppresses this one device
        # unless the analyst explicitly asked for --all-assets.
        asset_id: int | None = None
        if not all_assets and finding.matched_asset:
            asset_row = await session.execute(
                select(CustomerAsset.id).where(
                    CustomerAsset.customer_id == finding.customer_id,
                    CustomerAsset.asset_value == finding.matched_asset,
                ).limit(1)
            )
            asset_id = asset_row.scalar_one_or_none()

        fp_hash = compute_fp_hash(finding.ioc_type, finding.ioc_value)
        fp_scope_asset_id = asset_id if not all_assets else None

        # Idempotent on (customer_id, asset_id, ioc_type, ioc_value_hash) —
        # matches the uq_fp_memory constraint. Re-marking the same
        # (finding, scope) pair updates the existing rule instead of
        # raising IntegrityError (this legitimately happens: an analyst
        # scope-testing FP rules, or the same CVE recurring on the same
        # asset after being reopened).
        existing = await session.execute(
            select(FpMemory).where(
                FpMemory.customer_id == finding.customer_id,
                FpMemory.asset_id == fp_scope_asset_id
                if fp_scope_asset_id is not None else FpMemory.asset_id.is_(None),
                FpMemory.ioc_type == finding.ioc_type,
                FpMemory.ioc_value_hash == fp_hash,
            )
        )
        fp = existing.scalar_one_or_none()
        if fp:
            fp.reason = reason
            fp.marked_by = who
        else:
            fp = FpMemory(
                customer_id=finding.customer_id,
                asset_id=fp_scope_asset_id,
                ioc_type=finding.ioc_type,
                ioc_value_hash=fp_hash,
                ioc_value_sample=finding.ioc_value[:200],
                reason=reason,
                marked_by=who,
            )
            session.add(fp)

        finding.status = FindingStatus.FALSE_POSITIVE
        finding.closed_at = datetime.now(timezone.utc)
        finding.closed_by = who
        finding.closed_reason = f"FP: {reason}"
        await session.commit()

    scope_msg = "all assets của customer" if all_assets else f"asset đơn (#{asset_id})"
    await message.answer(
        f"✅ Finding #{finding_id} marked FP (scope: {scope_msg})\n"
        f"Reason: {reason}\nFuture matches sẽ auto-close với scope này."
    )


# ── /reopen <finding_id> --reason=X ─────────────────────────────────────────

@router.message(Command("reopen"))
@log_command("reopen")
async def cmd_reopen(message: Message):
    args = parse_args(message.text or "", "reopen")
    pos = args.get("_positional", [])
    reason = args.get("reason")
    if not pos or not reason:
        await message.answer("Cú pháp: /reopen <finding_id> --reason=X")
        return
    try:
        finding_id = int(pos[0])
    except ValueError:
        await message.answer(f"finding_id không hợp lệ: {pos[0]}")
        return
    who = message.from_user.username or str(message.from_user.id)

    async with async_session() as session:
        finding = await session.get(Finding, finding_id)
        if not finding:
            await message.answer(f"Không tìm thấy Finding #{finding_id}")
            return
        if finding.status == FindingStatus.OPEN:
            await message.answer(f"Finding #{finding_id} đã open.")
            return
        prev_status = finding.status.value
        finding.status = FindingStatus.OPEN
        finding.closed_at = None
        finding.closed_by = None
        finding.closed_reason = f"reopened by @{who}: {reason} (was {prev_status})"
        await session.commit()
    await message.answer(f"✅ Finding #{finding_id} reopened (was {prev_status}) by @{who}")


# ── /silence <finding_id> --hours=N ─────────────────────────────────────────
# Tracked in Finding.metadata_ (no schema change) — Bot 1's _dispatch_single
# checks metadata_.silenced_until before sending.

@router.message(Command("silence"))
@log_command("silence")
async def cmd_silence(message: Message):
    args = parse_args(message.text or "", "silence")
    pos = args.get("_positional", [])
    hours_str = args.get("hours")
    if not pos or not hours_str:
        await message.answer("Cú pháp: /silence <finding_id> --hours=N")
        return
    try:
        finding_id = int(pos[0])
        hours = int(hours_str)
    except ValueError:
        await message.answer("finding_id hoặc hours không hợp lệ")
        return
    if hours < 1 or hours > 720:
        await message.answer("--hours phải trong 1-720.")
        return

    silenced_until = datetime.now(timezone.utc) + timedelta(hours=hours)
    who = message.from_user.username or str(message.from_user.id)

    async with async_session() as session:
        finding = await session.get(Finding, finding_id)
        if not finding:
            await message.answer(f"Không tìm thấy Finding #{finding_id}")
            return
        meta = dict(finding.metadata_ or {})
        meta["silenced_until"] = silenced_until.isoformat()
        meta["silenced_by"] = who
        finding.metadata_ = meta
        await session.commit()
    await message.answer(
        f"🔇 Finding #{finding_id} silenced đến "
        f"{silenced_until.strftime('%d/%m/%Y %H:%M')} UTC by @{who}"
    )
