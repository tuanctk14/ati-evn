"""/delete_ioc <detection_id> --confirm [--acknowledge-findings]

Soft-delete. Only source='internal' (feed IOCs are immutable via bot). If
the IOC has related Findings, requires --acknowledge-findings in addition
to --confirm — Findings themselves are retained as evidence, only the IOC
is hidden.
"""
from __future__ import annotations

from datetime import datetime, timezone

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message
from sqlalchemy import func, select

from ati_evn.db.models import Detection, Finding
from ati_evn.db.session import async_session
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command

router = Router()


@router.message(Command("delete_ioc"))
@log_command("delete_ioc")
async def cmd_delete_ioc(message: Message):
    args = parse_args(message.text or "", "delete_ioc")
    pos = args.get("_positional", [])
    if not pos or not args.get("confirm"):
        await message.answer("Cú pháp: /delete_ioc <detection_id> --confirm [--acknowledge-findings]")
        return
    try:
        detection_id = int(pos[0])
    except ValueError:
        await message.answer(f"detection_id không hợp lệ: {pos[0]}")
        return
    who = message.from_user.username or str(message.from_user.id)

    async with async_session() as session:
        det = await session.get(Detection, detection_id)
        if not det:
            await message.answer(f"Không tìm thấy IOC #{detection_id}")
            return
        if det.deleted_at:
            await message.answer(f"IOC #{detection_id} đã bị soft-delete từ trước.")
            return
        if det.source != "internal":
            await message.answer(
                f"IOC #{detection_id} có source='{det.source}' — chỉ IOC "
                f"source='internal' mới xóa được qua bot."
            )
            return

        finding_count = (await session.execute(
            select(func.count(Finding.id)).where(
                Finding.ioc_type == det.ioc_type,
                Finding.ioc_value == det.ioc_value,
            )
        )).scalar() or 0

        if finding_count > 0 and not args.get("acknowledge-findings"):
            await message.answer(
                f"⚠️ IOC #{detection_id} có {finding_count} Finding liên quan.\n"
                f"Xóa IOC sẽ ẩn nó. Finding vẫn giữ nguyên (evidence).\n\n"
                f"Nếu bạn hiểu và vẫn muốn xóa, chạy:\n"
                f"/delete_ioc {detection_id} --confirm --acknowledge-findings"
            )
            return

        det.deleted_at = datetime.now(timezone.utc)
        det.deleted_by = who
        await session.commit()

    await message.answer(f"✅ IOC #{detection_id} đã soft-delete.")
