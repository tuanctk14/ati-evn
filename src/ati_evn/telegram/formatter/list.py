"""Format paginated Finding list -> Bot 2 /list_open response."""
from __future__ import annotations

import math

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from ati_evn.telegram.formatter.common import fmt_dt, fmt_severity, truncate


def format_finding_list(findings_page, total, page, per_page) -> str:
    total_pages = max(1, math.ceil(total / per_page))

    lines = [f"📋 Finding list — {total} kết quả (trang {page}/{total_pages})", ""]

    if not findings_page:
        lines.append("(không có kết quả)")
    else:
        for row in findings_page:
            finding, customer_name = row
            ioc = truncate(finding.ioc_value, 50)
            lines.append(
                f"#{finding.id} {fmt_severity(finding.severity.value)} "
                f"{ioc} — {customer_name} — {fmt_dt(finding.first_seen)}"
            )

    lines.append("")
    lines.append(f"Trang {page}/{total_pages}.")

    return "\n".join(lines)


def list_open_pagination_keyboard(
    page: int, total_pages: int, severity: str | None, customer: str | None,
) -> InlineKeyboardMarkup | None:
    """Prev/Next buttons for /list_open. callback_data format:
    'lo:{page}:{severity}:{customer}' -- '-' stands in for an unset filter
    since callback_data can't contain empty segments cleanly with split(':').
    """
    if total_pages <= 1:
        return None

    sev_tok = severity or "-"
    cust_tok = customer or "-"
    buttons = []
    if page > 1:
        buttons.append(InlineKeyboardButton(
            text="◀ Trang trước", callback_data=f"lo:{page - 1}:{sev_tok}:{cust_tok}",
        ))
    if page < total_pages:
        buttons.append(InlineKeyboardButton(
            text="Trang sau ▶", callback_data=f"lo:{page + 1}:{sev_tok}:{cust_tok}",
        ))
    if not buttons:
        return None
    return InlineKeyboardMarkup(inline_keyboard=[buttons])
