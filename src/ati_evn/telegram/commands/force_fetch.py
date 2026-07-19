"""/force_fetch [--feed=nvd|threatfox|malwarebazaar|urlhaus|feodo|all]

Manual trigger for analyst debug — bypasses the scheduler interval.
"""
from __future__ import annotations

import logging

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message

from ati_evn.fetchers.scheduler import _get_feed_specs, run_feed_once
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command

logger = logging.getLogger("ati_evn.telegram.force_fetch")
router = Router()

VALID_FEEDS = {"nvd", "threatfox", "malwarebazaar", "urlhaus", "feodo", "all"}


@router.message(Command("force_fetch"))
@log_command("force_fetch")
async def cmd_force_fetch(message: Message):
    args = parse_args(message.text or "", "force_fetch")
    feed = (args.get("feed") or "all").lower()

    if feed not in VALID_FEEDS:
        await message.answer(
            "Cú pháp: /force_fetch [--feed=nvd|threatfox|malwarebazaar|urlhaus|feodo|all]\n"
            f"Feed không hợp lệ: {feed}"
        )
        return

    feeds_to_run = [s.name for s in _get_feed_specs()] if feed == "all" else [feed]

    thinking = await message.answer(
        f"🔄 Đang chạy fetcher: {', '.join(feeds_to_run)}\n"
        f"⏳ Mỗi feed 5-30s, tổng có thể lên 2-3 phút cho all."
    )

    results = {}
    for f in feeds_to_run:
        try:
            r = await run_feed_once(f, trigger_reason="manual_force_fetch")
            results[f] = r
        except Exception as e:
            results[f] = {"status": "error", "error": str(e)[:200]}

    await thinking.delete()

    lines = ["✅ Fetch complete:", ""]
    for f, r in results.items():
        status = r.get("status", "?")
        if status == "success":
            added = r.get("added", 0)
            updated = r.get("updated", 0)
            lines.append(f"  {f}: OK — {added} added, {updated} updated")
        elif status == "skipped":
            lines.append(f"  {f}: SKIPPED — {r.get('error', '?')[:100]}")
        else:
            lines.append(f"  {f}: FAIL — {r.get('error', '?')[:100]}")
    await message.answer("\n".join(lines))
