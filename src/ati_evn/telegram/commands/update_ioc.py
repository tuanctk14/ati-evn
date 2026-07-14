"""/update_ioc <detection_id> [--severity=X] [--expire=Nd|clear] [--note=X]

Only source='internal' detections are updatable (feed IOCs are read-only).
If --severity changes and the IOC already produced Findings, propagates the
new severity to those Findings — unless they're closed/FP/expired.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message
from sqlalchemy import select

from ati_evn.db.models import Detection, Finding, FindingStatus, Severity
from ati_evn.db.session import async_session
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command

router = Router()

_SKIP_STATUSES = {FindingStatus.CLOSED, FindingStatus.FALSE_POSITIVE, FindingStatus.EXPIRED}


@router.message(Command("update_ioc"))
@log_command("update_ioc")
async def cmd_update_ioc(message: Message):
    args = parse_args(message.text or "", "update_ioc")
    pos = args.get("_positional", [])
    if not pos:
        await message.answer(
            "Cú pháp: /update_ioc <detection_id> [--severity=X] "
            "[--expire=Nd|clear] [--note=X]"
        )
        return
    try:
        detection_id = int(pos[0])
    except ValueError:
        await message.answer(f"detection_id không hợp lệ: {pos[0]}")
        return

    async with async_session() as session:
        det = await session.get(Detection, detection_id)
        if not det:
            await message.answer(f"Không tìm thấy IOC #{detection_id}")
            return
        if det.deleted_at:
            await message.answer(f"IOC #{detection_id} đang bị soft-delete. Restore trước khi update.")
            return
        if det.source != "internal":
            await message.answer(
                f"IOC #{detection_id} có source='{det.source}' — chỉ IOC "
                f"source='internal' mới update được qua bot."
            )
            return

        changes: dict[str, tuple] = {}
        severity_changed = False

        new_severity = args.get("severity")
        if new_severity:
            try:
                sev = Severity(new_severity.upper())
            except ValueError:
                await message.answer(f"severity không hợp lệ: {new_severity}")
                return
            if sev != det.severity:
                changes["severity"] = (det.severity.value, sev.value)
                det.severity = sev
                severity_changed = True

        new_expire = args.get("expire")
        if new_expire is not None:
            if str(new_expire).lower() == "clear":
                if det.expires_at is not None:
                    changes["expires_at"] = (det.expires_at.isoformat(), None)
                    det.expires_at = None
            else:
                expire_str = str(new_expire).lower().strip()
                if expire_str.endswith("d") and expire_str[:-1].isdigit():
                    new_dt = datetime.now(timezone.utc) + timedelta(days=int(expire_str[:-1]))
                    changes["expires_at"] = (
                        det.expires_at.isoformat() if det.expires_at else None,
                        new_dt.isoformat(),
                    )
                    det.expires_at = new_dt
                else:
                    await message.answer(f"--expire format không hợp lệ: {expire_str} (dùng '30d' hoặc 'clear')")
                    return

        new_note = args.get("note")
        if new_note and new_note != det.raw_text:
            changes["raw_text"] = (det.raw_text, new_note)
            det.raw_text = new_note

        if not changes:
            await message.answer("Không có thay đổi.")
            return

        findings_updated = 0
        if severity_changed:
            fnd_rows = await session.execute(
                select(Finding).where(
                    Finding.ioc_type == det.ioc_type,
                    Finding.ioc_value == det.ioc_value,
                )
            )
            for f in fnd_rows.scalars():
                if f.status in _SKIP_STATUSES:
                    continue
                f.severity = det.severity
                findings_updated += 1

        await session.commit()

    changes_str = "\n".join(f"  {k}: {v[0]} → {v[1]}" for k, v in changes.items())
    reply = f"✅ IOC #{detection_id} updated:\n{changes_str}"
    if findings_updated:
        reply += f"\n\nĐã cập nhật severity cho {findings_updated} Finding liên quan."
    await message.answer(reply)
