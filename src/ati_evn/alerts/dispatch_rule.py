"""Decide whether a Finding warrants a Telegram alert.

Rule (slice 3 confirmed):
  HIGH+ severity                    → dispatch
  MEDIUM severity + source_count>=2 → dispatch
  Everything else                   → skip (dashboard-only)
"""
from __future__ import annotations

from ati_evn.db.models import Finding, Severity


def should_dispatch(finding: Finding) -> tuple[bool, str]:
    if finding.severity in (Severity.HIGH, Severity.CRITICAL):
        return True, f"severity={finding.severity.value}"
    if finding.severity == Severity.MEDIUM and (finding.source_count or 0) >= 2:
        return True, f"MEDIUM+{finding.source_count}sources"
    return False, f"below threshold ({finding.severity.value})"
