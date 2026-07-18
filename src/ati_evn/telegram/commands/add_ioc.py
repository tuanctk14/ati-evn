"""/add_ioc --type=T --value=V [--severity=X] [--note=N] [--expire=30d]
            [--malware=<family_name>]

Creates a Detection with source='internal'. If --expire=Nd, sets
Detection.expires_at = now + N days (TTL worker will transition
Finding.status -> EXPIRED when reached).

--malware tags the Detection with a malware family name (stored as
metadata_["malware_printable"], the same field feeds like ThreatFox
populate) so the enrichment orchestrator's Malware->S-series lookup
(slice 6.1) can attribute real ATT&CK techniques instead of falling
back to the generic per-IOC-type heuristic. Not validated against the
MITRE catalog here — any name analysts type is accepted; the
enrichment lookup itself resolves or gracefully falls back.

Runs an immediate matcher pass (via customer_router) — matched assets
-> Findings -> alert_queue -> Bot 1 dispatch.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message

from ati_evn.db.models import Detection, DetectionStatus, Severity
from ati_evn.db.session import async_session
from ati_evn.match.customer_router import route_detections
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command

logger = logging.getLogger("ati_evn.telegram.add_ioc")
router = Router()

VALID_IOC_TYPES = {"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email", "cve_id"}


@router.message(Command("add_ioc"))
@log_command("add_ioc")
async def cmd_add_ioc(message: Message):
    args = parse_args(message.text or "", "add_ioc")
    ioc_type = (args.get("type") or "").lower()
    value = args.get("value")
    if not ioc_type or not value:
        await message.answer(
            "Cú pháp: /add_ioc --type=T --value=V [--severity=X] "
            "[--note=N] [--expire=Nd] [--malware=<family_name>]"
        )
        return
    if ioc_type not in VALID_IOC_TYPES:
        await message.answer(f"ioc_type không hợp lệ: {ioc_type}\nValid: {sorted(VALID_IOC_TYPES)}")
        return

    severity_str = (args.get("severity") or "MEDIUM").upper()
    try:
        severity = Severity(severity_str)
    except ValueError:
        await message.answer(f"severity không hợp lệ: {severity_str}")
        return

    who = message.from_user.username or str(message.from_user.id)
    note = args.get("note") or f"Manual IOC added by analyst {who}"

    expires_at = None
    if args.get("expire"):
        expire_str = str(args["expire"]).lower().strip()
        if expire_str.endswith("d") and expire_str[:-1].isdigit():
            expires_at = datetime.now(timezone.utc) + timedelta(days=int(expire_str[:-1]))
        else:
            await message.answer(f"--expire format không hợp lệ: {expire_str} (dùng '30d')")
            return

    malware = args.get("malware")
    det_metadata = {"added_by": who}
    if malware:
        det_metadata["malware_printable"] = malware

    async with async_session() as session:
        det = Detection(
            source="internal",
            ioc_type=ioc_type,
            ioc_value=value.lower().strip(),
            raw_text=note,
            severity=severity,
            status=DetectionStatus.NEW,
            expires_at=expires_at,
            metadata_=det_metadata,
        )
        session.add(det)
        await session.commit()
        detection_id = det.id

    thinking = await message.answer("🔍 Đang match với asset EVN...")

    try:
        async with async_session() as session:
            stats = await route_detections(session, only_new=True)
    except Exception as e:
        await thinking.delete()
        logger.exception("Matcher after /add_ioc failed: %s", e)
        await message.answer(f"IOC #{detection_id} đã tạo nhưng matcher lỗi: {str(e)[:200]}")
        return

    await thinking.delete()

    reply = (
        f"✅ IOC #{detection_id} đã thêm:\n"
        f"  Type: {ioc_type}\n"
        f"  Value: {value}\n"
        f"  Severity: {severity.value}\n"
        f"  Source: internal\n"
    )
    if malware:
        reply += f"  Malware: {malware}\n"
    if expires_at:
        reply += f"  Expires: {expires_at.strftime('%d/%m/%Y %H:%M')} UTC\n"

    reply += (
        f"\nMatcher: {stats.detections_matched} matched, "
        f"{stats.findings_created} finding(s) created"
    )
    if stats.findings_created > 0:
        reply += "\n\n🚨 Bot 1 sẽ dispatch alert nếu severity đủ threshold."
    await message.answer(reply)
