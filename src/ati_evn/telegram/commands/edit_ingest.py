"""/edit_ingest <session_id> [--drop=1,3,5] [--drop-cves=2,4]

Drop-based edit. Indexes are 1-based, referring to the CURRENT preview
state (reshuffled after previous edits).

After edit: show refreshed preview with new indexes.
"""
from __future__ import annotations

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message

from ati_evn.db.models import IngestionSession
from ati_evn.db.session import async_session
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command
from ati_evn.telegram.formatter.ingestion import format_preview

router = Router()


def _parse_indexes(s, list_len: int) -> set[int]:
    """Parse '1,3,5' or '2-4' to a set of 0-based indexes, clamped to
    the valid range for the current list."""
    if not s or s is True:
        return set()
    out: set[int] = set()
    for tok in str(s).split(","):
        tok = tok.strip()
        if not tok:
            continue
        if "-" in tok:
            try:
                lo, hi = tok.split("-", 1)
                for i in range(int(lo), int(hi) + 1):
                    if 1 <= i <= list_len:
                        out.add(i - 1)
            except ValueError:
                continue
        else:
            try:
                i = int(tok)
                if 1 <= i <= list_len:
                    out.add(i - 1)
            except ValueError:
                continue
    return out


@router.message(Command("edit_ingest"))
@log_command("edit_ingest")
async def cmd_edit_ingest(message: Message):
    args = parse_args(message.text or "", "edit_ingest")
    pos = args.get("_positional", [])
    if not pos:
        await message.answer(
            "Cú pháp: /edit_ingest <id> [--drop=1,3,5] [--drop-cves=2,4]\n"
            "Indexes 1-based, theo preview hiện tại."
        )
        return
    try:
        sid = int(pos[0])
    except ValueError:
        await message.answer(f"session_id không hợp lệ: {pos[0]}")
        return

    async with async_session() as session:
        ingest = await session.get(IngestionSession, sid)
        if not ingest:
            await message.answer(f"Session #{sid} không tồn tại.")
            return
        if ingest.status != "pending":
            await message.answer(
                f"Session #{sid} status={ingest.status}, chỉ pending mới edit được."
            )
            return

        data = dict(ingest.extracted_data or {})
        iocs = list(data.get("iocs") or [])
        cves = list(data.get("cves") or [])

        drop_iocs = _parse_indexes(args.get("drop"), len(iocs))
        drop_cves = _parse_indexes(args.get("drop-cves"), len(cves))

        n_dropped_i = len(drop_iocs)
        n_dropped_c = len(drop_cves)

        if not drop_iocs and not drop_cves:
            await message.answer(
                "Không có gì để drop. Xem preview hiện tại + gõ lại "
                "/edit_ingest với --drop=... hoặc --drop-cves=..."
            )
            return

        data["iocs"] = [io for i, io in enumerate(iocs) if i not in drop_iocs]
        data["cves"] = [c for i, c in enumerate(cves) if i not in drop_cves]
        ingest.extracted_data = data
        await session.commit()

        preview = format_preview(
            sid, ingest.source_type, ingest.source_url, ingest.source_filename, data,
        )

    header = f"✏️ Session #{sid} edited: dropped {n_dropped_i} IOC(s) + {n_dropped_c} CVE(s)\n\n"
    combined = header + preview
    if len(combined) > 3800:
        await message.answer(header)
        parts_ = preview.split("\n\n")
        buf = ""
        for p in parts_:
            if len(buf) + len(p) + 2 > 3800:
                await message.answer(buf, disable_web_page_preview=True)
                buf = p
            else:
                buf = (buf + "\n\n" + p) if buf else p
        if buf:
            await message.answer(buf, disable_web_page_preview=True)
    else:
        await message.answer(combined, disable_web_page_preview=True)
