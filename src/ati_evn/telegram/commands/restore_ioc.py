"""/restore_ioc <detection_id>

Only source='internal'. Resets status to NEW and re-runs the matcher
scoped to just this detection.
"""
from __future__ import annotations

import logging

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message

from ati_evn.db.models import Detection, DetectionStatus
from ati_evn.db.session import async_session
from ati_evn.match.customer_router import route_detections
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command

logger = logging.getLogger("ati_evn.telegram.restore_ioc")
router = Router()


@router.message(Command("restore_ioc"))
@log_command("restore_ioc")
async def cmd_restore_ioc(message: Message):
    args = parse_args(message.text or "", "restore_ioc")
    pos = args.get("_positional", [])
    if not pos:
        await message.answer("Cú pháp: /restore_ioc <detection_id>")
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
        if not det.deleted_at:
            await message.answer(f"IOC #{detection_id} đang active (chưa bị delete).")
            return
        if det.source != "internal":
            await message.answer(
                f"IOC #{detection_id} có source='{det.source}' — chỉ IOC "
                f"source='internal' mới restore được qua bot."
            )
            return

        det.deleted_at = None
        det.deleted_by = None
        det.status = DetectionStatus.NEW
        await session.commit()

    try:
        async with async_session() as session:
            await route_detections(session, detection_ids=[detection_id])
    except Exception as e:
        logger.exception("Matcher after /restore_ioc failed: %s", e)
        await message.answer(f"IOC #{detection_id} đã restore nhưng matcher lỗi: {str(e)[:200]}")
        return

    await message.answer(f"✅ IOC #{detection_id} restored. Matcher đã chạy lại.")
