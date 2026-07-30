"""Format Customer detail -> Bot 2 /customer response."""
from __future__ import annotations


def format_customer_detail(
    customer, asset_breakdown, finding_counts, recent_alerts, top_techniques,
    parent_name: str | None = None,
    ti_counts: list | None = None, ti_total: int = 0,
) -> str:
    lines = [
        f"🏢 {customer.name}",
        "",
        f"Short code: {customer.short_code or '-'}",
        f"Parent: {parent_name or '-'}",
        f"Industry: {customer.industry or '-'}",
        f"Primary domain: {customer.primary_domain or '-'}",
        f"Tier: {customer.tier or '-'}",
        f"Active: {customer.active}",
    ]

    if asset_breakdown:
        lines.append("")
        lines.append("Assets by type:")
        for asset_type, count in sorted(asset_breakdown.items(), key=lambda x: -x[1]):
            lines.append(f"  • {asset_type}: {count}")

    if finding_counts:
        lines.append("")
        lines.append("Findings by severity (30 ngày qua):")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if sev in finding_counts:
                lines.append(f"  • {sev}: {finding_counts[sev]}")

    if ti_counts:
        lines.append("")
        lines.append(f"Threat Indicators (30 ngày qua): {ti_total}")
        for tp, count in ti_counts:
            lines.append(f"  • {tp}: {count}")

    lines.append("")
    lines.append(f"Alerts (24h qua): {recent_alerts}")

    if top_techniques:
        lines.append("")
        lines.append("Top ATT&CK techniques (30 ngày qua):")
        for tech_id, count in top_techniques[:3]:
            lines.append(f"  • {tech_id}: {count} lần")

    return "\n".join(lines)
