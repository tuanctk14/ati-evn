"""Format paginated Finding list -> Bot 2 /list_open response."""
from __future__ import annotations

import math

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
    if page < total_pages:
        lines.append(f"Trang {page}/{total_pages}. Dùng --page={page + 1} để xem tiếp.")
    else:
        lines.append(f"Trang {page}/{total_pages}.")

    return "\n".join(lines)
