"""Format IOC detail -> Bot 2 /ioc response."""
from __future__ import annotations

from ati_evn.telegram.formatter.common import fmt_dt, fmt_severity


def format_ioc_detail(ioc_type, ioc_value, detections, related_findings) -> str:
    sources = sorted({d.source for d in detections})
    severities = sorted({d.severity.value for d in detections})
    first_seen = min((d.first_seen for d in detections), default=None)
    last_seen = max((d.last_seen for d in detections), default=None)

    lines = [
        f"🔎 IOC: {ioc_value} ({ioc_type.upper()})",
        "",
        f"Feed sources: {', '.join(sources) if sources else 'unknown'}",
        f"Severity seen: {', '.join(severities) if severities else '-'}",
        f"First seen: {fmt_dt(first_seen)} ICT",
        f"Last seen : {fmt_dt(last_seen)} ICT",
        f"Detections: {len(detections)}",
        "",
        f"Related Findings: {len(related_findings)}",
    ]
    for f in related_findings[:5]:
        lines.append(f"  • #{f.id} {fmt_severity(f.severity.value)} — customer_id={f.customer_id}")
    if len(related_findings) > 5:
        lines.append(f"  ...và {len(related_findings) - 5} finding khác")

    return "\n".join(lines)
