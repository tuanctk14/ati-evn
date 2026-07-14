"""Format global stats -> Bot 2 /stats response."""
from __future__ import annotations


def format_stats(counters, top_customers, top_techniques, dispatch_stats) -> str:
    lines = [
        "📊 ATI-EVN — Tổng quan hệ thống",
        "",
        f"Findings: {counters.get('findings_total', 0)} total",
    ]

    by_status = counters.get("findings_by_status") or {}
    if by_status:
        lines.append("  Theo status: " + ", ".join(
            f"{k}={v}" for k, v in sorted(by_status.items(), key=lambda x: -x[1])
        ))

    by_severity = counters.get("findings_by_severity") or {}
    if by_severity:
        lines.append("  Theo severity: " + ", ".join(
            f"{k}={v}" for k, v in sorted(by_severity.items(), key=lambda x: -x[1])
        ))

    lines.append("")
    lines.append(f"Detections: {counters.get('detections_total', 0)} total")
    by_source = counters.get("detections_by_source") or []
    if by_source:
        lines.append("  Top sources: " + ", ".join(f"{s}={c}" for s, c in by_source[:5]))

    lines.append("")
    lines.append("Alerts (24h qua):")
    lines.append(
        f"  Sent={dispatch_stats.get('dispatched', 0)} "
        f"Deduped={dispatch_stats.get('deduped', 0)} "
        f"Batched={dispatch_stats.get('batched', 0)} "
        f"Failed={dispatch_stats.get('failed', 0)}"
    )

    if top_customers:
        lines.append("")
        lines.append("Top 5 customer theo open findings:")
        for name, count in top_customers[:5]:
            lines.append(f"  • {name}: {count}")

    if top_techniques:
        lines.append("")
        lines.append("Top 5 ATT&CK techniques (7 ngày qua):")
        for tech_id, count in top_techniques[:5]:
            lines.append(f"  • {tech_id}: {count} lần")

    vendors = counters.get("top_vendors") or []
    if vendors:
        lines.append("")
        lines.append("Top 5 vendor theo finding count:")
        for vendor, count in vendors[:5]:
            lines.append(f"  • {vendor}: {count}")

    latest_ingest = counters.get("latest_ingest")
    if latest_ingest:
        lines.append("")
        lines.append(f"Ingest gần nhất: {latest_ingest}")

    return "\n".join(lines)
