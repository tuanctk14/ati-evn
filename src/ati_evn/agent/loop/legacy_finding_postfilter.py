"""Rewrite agent suggestions of /close, /mark_fp, /reopen <id> when
<id> is a legacy non-CVE Finding (ioc_type != "cve_id") -- these rows
predate the slice 15A Finding/ThreatIndicator split and have no
close/mark_fp/reopen lifecycle (action.py's guard rejects the call at
execution time), but the LLM sometimes suggests the command anyway
despite the SYSTEM_PROMPT rule against it. This is a defense-in-depth
layer: the execution guard in telegram/commands/action.py is what
actually prevents the wrong action; this only cleans up the suggestion
text so the analyst isn't pointed at a command that will just bounce.
"""
from __future__ import annotations

import logging
import re

from sqlalchemy import select

from ati_evn.db.models import Finding
from ati_evn.db.session import async_session

logger = logging.getLogger("ati_evn.agent.legacy_finding_postfilter")

_ACTION_RE = re.compile(
    r"/(close|mark_fp|reopen)\s+(\d+)", re.IGNORECASE,
)


async def postfilter_legacy_finding_actions(text: str) -> tuple[str, dict]:
    """Return (cleaned_text, stats). stats: {"rewritten": [(orig, id), ...]}."""
    if not text:
        return text, {"rewritten": []}

    matches = list(_ACTION_RE.finditer(text))
    if not matches:
        return text, {"rewritten": []}

    finding_ids = {int(m.group(2)) for m in matches}
    async with async_session() as session:
        rows = await session.execute(
            select(Finding.id, Finding.ioc_type, Finding.metadata_).where(
                Finding.id.in_(finding_ids),
            )
        )
        # migrated_to_ti_id (set by the slice 15A migration script) is the
        # ONLY reliable Finding.id -> ThreatIndicator.id mapping -- these
        # are two independent auto-increment sequences, so the raw
        # Finding.id is never a valid /acknowledge_indicator argument.
        finding_info = {
            fid: (ioc_type, (metadata or {}).get("migrated_to_ti_id"))
            for fid, ioc_type, metadata in rows.all()
        }

    rewritten: list[tuple[str, int]] = []

    def _replace(m: re.Match) -> str:
        cmd, fid_str = m.group(1), m.group(2)
        fid = int(fid_str)
        info = finding_info.get(fid)
        if info is None or info[0] == "cve_id":
            return m.group(0)
        ti_id = info[1]
        if ti_id is None:
            return m.group(0)
        rewritten.append((m.group(0), ti_id))
        return f"/acknowledge_indicator {ti_id}"

    cleaned = _ACTION_RE.sub(_replace, text)
    if rewritten:
        logger.info(
            "Legacy-finding postfilter: rewrote %d suggestion(s): %s",
            len(rewritten), rewritten,
        )
    return cleaned, {"rewritten": rewritten}
