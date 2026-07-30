"""Format global stats -> Bot 2 /stats response."""
from __future__ import annotations


def format_stats(counters, top_customers, top_techniques, dispatch_stats) -> str:
    lines = [
        "📊 ATI-EVN — Tổng quan hệ thống",
        "",
        f"Findings: {counters.get('findings_total', 0)}",
    ]

    by_status = counters.get("findings_by_status") or {}
    if by_status:
        lines.append("  Theo status:")
        for k, v in sorted(by_status.items(), key=lambda x: -x[1]):
            lines.append(f"    • {k}: {v}")

    by_severity = counters.get("findings_by_severity") or {}
    if by_severity:
        lines.append("  Theo severity:")
        for k, v in sorted(by_severity.items(), key=lambda x: -x[1]):
            lines.append(f"    • {k}: {v}")

    lines.append("")
    lines.append(f"Threat Indicators: {counters.get('ti_total', 0)}")
    ti_by_status = counters.get("ti_by_status") or {}
    if ti_by_status:
        lines.append("  Theo status:")
        for k, v in sorted(ti_by_status.items(), key=lambda x: -x[1]):
            lines.append(f"    • {k}: {v}")
    ti_by_type = counters.get("ti_by_type") or []
    if ti_by_type:
        lines.append("  Theo loại:")
        for tp, cnt in ti_by_type[:6]:
            lines.append(f"    • {tp}: {cnt}")

    lines.append("")
    lines.append(f"Dữ liệu thu thập: {counters.get('detections_total', 0)}")
    by_source = counters.get("detections_by_source") or []
    if by_source:
        lines.append("  Top nguồn:")
        for s, c in by_source[:5]:
            lines.append(f"    • {s}: {c}")

    lines.append("")
    lines.append("Alert đã gửi analyst (24h qua):")
    lines.append(f"    • Sent: {dispatch_stats.get('dispatched', 0)}")
    lines.append(f"    • Deduped: {dispatch_stats.get('deduped', 0)}")
    lines.append(f"    • Batched: {dispatch_stats.get('batched', 0)}")
    lines.append(f"    • Failed: {dispatch_stats.get('failed', 0)}")

    if top_customers:
        lines.append("")
        lines.append("Top 5 customer theo open findings:")
        for name, count in top_customers[:5]:
            lines.append(f"  • {name}: {count}")

    if top_techniques:
        lines.append("")
        lines.append("Top 5 ATT&CK technique trong Finding (7 ngày qua):")
        for tech_id, count in top_techniques[:5]:
            lines.append(f"  • {tech_id}: {count} finding")

    vendors = counters.get("top_vendors") or []
    if vendors:
        lines.append("")
        lines.append("Top 5 vendor theo finding count:")
        for vendor, count in vendors[:5]:
            lines.append(f"  • {vendor}: {count}")

    latest_ingest = counters.get("latest_ingest")
    if latest_ingest:
        lines.append("")
        lines.append(f"Fetch gần nhất: {latest_ingest}")

    return "\n".join(lines)
