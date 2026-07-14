"""Shared formatting: dates in dd/mm/yyyy HH:MM, escape MarkdownV2, truncate
long strings, emojis for severity."""
from __future__ import annotations

from datetime import datetime, timedelta


def fmt_dt(dt: datetime | None, default: str = "-") -> str:
    if not dt:
        return default
    # Assume UTC in DB; convert to ICT (UTC+7)
    ict = dt + timedelta(hours=7) if dt.tzinfo else dt
    return ict.strftime("%d/%m/%Y %H:%M")


def fmt_severity(sev: str) -> str:
    emoji = {"CRITICAL": "🔴", "HIGH": "🚨", "MEDIUM": "⚠️", "LOW": "ℹ️"}
    return f"{emoji.get(sev, '•')} {sev}"


def truncate(s: str | None, n: int) -> str:
    if not s:
        return ""
    s = str(s)
    return s if len(s) <= n else s[:n - 1] + "…"


def escape_md(s: str) -> str:
    """Escape Telegram MarkdownV2 special chars. Use only if sending with
    parse_mode='MarkdownV2'. For MVP we use plain text so this is optional."""
    if not s:
        return ""
    for c in "_*[]()~`>#+-=|{}.!\\":
        s = s.replace(c, f"\\{c}")
    return s
