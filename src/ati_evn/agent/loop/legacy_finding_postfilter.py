"""Rewrite agent suggestions that pair a lifecycle command with the
wrong entity type. Two directions, both defense-in-depth: the real
guard is telegram/commands/action.py (Finding side) and
acknowledge_indicator/note_indicator's own lookups (ThreatIndicator
side) rejecting the call at execution time -- this only cleans up the
suggestion text so the analyst isn't pointed at a command that will
just bounce.

Direction 1 (original): /close, /mark_fp, /reopen <id> when <id> is a
legacy non-CVE Finding (ioc_type != "cve_id") -- these rows predate the
slice 15A Finding/ThreatIndicator split and have no
close/mark_fp/reopen lifecycle. Rewritten to /acknowledge_indicator via
Finding.metadata_['migrated_to_ti_id'] (set by the slice 15A migration
script -- the only reliable Finding.id -> ThreatIndicator.id mapping,
since the two are independent auto-increment sequences).

Direction 2 (new): /acknowledge_indicator, /note_indicator <id> when
<id> is actually a Finding id (CVE or otherwise) rather than a
ThreatIndicator id. There's no metadata link the other way (a Finding
row doesn't know a ThreatIndicator id points at it), so this can only
be flagged and removed, not rewritten to a specific replacement --
the correct command depends on the Finding's own lifecycle state
(/close vs /mark_fp vs /reopen), which the agent should determine by
re-checking the Finding, not have this postfilter guess.
"""
from __future__ import annotations

import logging
import re

from sqlalchemy import select

from ati_evn.db.models import Finding
from ati_evn.db.session import async_session

logger = logging.getLogger("ati_evn.agent.legacy_finding_postfilter")

_FINDING_CMD_RE = re.compile(
    r"/(close|mark_fp|reopen)\s+(\d+)", re.IGNORECASE,
)
_TI_CMD_RE = re.compile(
    r"/(acknowledge_indicator|note_indicator)\s+(\d+)(?:\s+\S.*)?", re.IGNORECASE,
)


async def postfilter_legacy_finding_actions(text: str) -> tuple[str, dict]:
    """Return (cleaned_text, stats). stats: {"rewritten": [(orig, id), ...]}."""
    if not text:
        return text, {"rewritten": []}

    finding_cmd_matches = list(_FINDING_CMD_RE.finditer(text))
    ti_cmd_matches = list(_TI_CMD_RE.finditer(text))
    if not finding_cmd_matches and not ti_cmd_matches:
        return text, {"rewritten": []}

    finding_ids = {int(m.group(2)) for m in finding_cmd_matches}
    finding_ids |= {int(m.group(2)) for m in ti_cmd_matches}

    async with async_session() as session:
        rows = await session.execute(
            select(Finding.id, Finding.ioc_type, Finding.metadata_).where(
                Finding.id.in_(finding_ids),
            )
        )
        finding_info = {
            fid: (ioc_type, (metadata or {}).get("migrated_to_ti_id"))
            for fid, ioc_type, metadata in rows.all()
        }

    rewritten: list[tuple[str, int]] = []

    def _replace_finding_cmd(m: re.Match) -> str:
        fid_str = m.group(2)
        fid = int(fid_str)
        info = finding_info.get(fid)
        if info is None or info[0] == "cve_id":
            return m.group(0)
        ti_id = info[1]
        if ti_id is None:
            return m.group(0)
        rewritten.append((m.group(0), ti_id))
        return f"/acknowledge_indicator {ti_id}"

    def _replace_ti_cmd(m: re.Match) -> str:
        cmd, fid_str = m.group(1), m.group(2)
        fid = int(fid_str)
        info = finding_info.get(fid)
        if info is None:
            # Not a known Finding id -- assume it's a real ThreatIndicator id.
            return m.group(0)
        rewritten.append((m.group(0), fid))
        return (
            f"[/{cmd} không áp dụng cho Finding #{fid} -- đây là CVE finding, "
            f"dùng /close hoặc /mark_fp thay thế]"
        )

    cleaned = _FINDING_CMD_RE.sub(_replace_finding_cmd, text)
    cleaned = _TI_CMD_RE.sub(_replace_ti_cmd, cleaned)
    if rewritten:
        logger.info(
            "Legacy-finding postfilter: rewrote %d suggestion(s): %s",
            len(rewritten), rewritten,
        )
    return cleaned, {"rewritten": rewritten}
