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
    """Return (cleaned_text, stats).

    stats: {"rewritten": [(orig_cmd, new_target), ...],  # Direction 1: Finding -> ThreatIndicator
            "blocked": [(orig_cmd, finding_id), ...]}     # Direction 2: TI command on a Finding id, blocked
    orig_cmd is truncated to the matched command itself (not any trailing
    text the regex also consumed) so trace lines built from this stay short.
    """
    if not text:
        return text, {"rewritten": [], "blocked": []}

    finding_cmd_matches = list(_FINDING_CMD_RE.finditer(text))
    ti_cmd_matches = list(_TI_CMD_RE.finditer(text))
    if not finding_cmd_matches and not ti_cmd_matches:
        return text, {"rewritten": [], "blocked": []}

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
    blocked: list[tuple[str, int]] = []

    def _replace_finding_cmd(m: re.Match) -> str:
        cmd, fid_str = m.group(1), m.group(2)
        fid = int(fid_str)
        info = finding_info.get(fid)
        if info is None or info[0] == "cve_id":
            return m.group(0)
        ti_id = info[1]
        if ti_id is None:
            return m.group(0)
        rewritten.append((f"/{cmd} {fid}", ti_id))
        return f"/acknowledge_indicator {ti_id}"

    def _replace_ti_cmd(m: re.Match) -> str:
        cmd, fid_str = m.group(1), m.group(2)
        fid = int(fid_str)
        info = finding_info.get(fid)
        if info is None:
            # Not a known Finding id -- assume it's a real ThreatIndicator id.
            return m.group(0)
        blocked.append((f"/{cmd} {fid}", fid))
        # Plain Vietnamese prose, not bracketed pseudo-syntax -- this text
        # gets embedded inline in the analyst-facing answer (not shown
        # separately), so it needs to read as a sentence, not a system note.
        return (
            f"#{fid} là Finding (CVE), không phải Threat Indicator, nên "
            f"/{cmd} không áp dụng -- dùng /close hoặc /mark_fp {fid} thay thế"
        )

    cleaned = _FINDING_CMD_RE.sub(_replace_finding_cmd, text)
    cleaned = _TI_CMD_RE.sub(_replace_ti_cmd, cleaned)
    if rewritten or blocked:
        logger.info(
            "Legacy-finding postfilter: %d rewritten, %d blocked: rewritten=%s blocked=%s",
            len(rewritten), len(blocked), rewritten, blocked,
        )
    return cleaned, {"rewritten": rewritten, "blocked": blocked}
