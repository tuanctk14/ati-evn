"""Format Finding detail -> Bot 2 /finding response."""
from __future__ import annotations

from ati_evn.telegram.formatter.common import fmt_dt, fmt_severity, truncate


def format_finding_detail(finding, customer, asset, ctx: dict) -> str:
    customer_name = customer.name if customer else f"Customer#{finding.customer_id}"
    asset_display = finding.matched_asset or "-"
    if asset is not None:
        parts = [asset.asset_value]
        if asset.product:
            detail = asset.product
            if asset.version:
                detail += f" v{asset.version}"
            parts.append(f"({detail})")
        asset_display = " ".join(parts)

    lines = [
        f"📋 Finding #{finding.id} — {fmt_severity(finding.severity.value)}",
        f"IOC: {finding.ioc_value} ({finding.ioc_type.upper()})",
        f"Title: {truncate(finding.title, 200)}",
        "",
        f"Customer: {customer_name}",
        f"Asset: {asset_display}",
        f"Match: {finding.correlation_type or '-'} (confidence {finding.confidence:.2f})"
        if finding.confidence is not None else f"Match: {finding.correlation_type or '-'}",
        f"Reason: {truncate(finding.detection_reason, 300)}",
        "",
        f"Sources: {', '.join(finding.sources or []) or 'unknown'} "
        f"({finding.source_count or 1} sources)",
        f"Status: {finding.status.value}",
        f"First seen: {fmt_dt(finding.first_seen)} ICT",
        f"Last seen : {fmt_dt(finding.last_seen)} ICT",
    ]

    techs = ctx.get("techniques") or []
    if techs:
        lines.append("")
        lines.append("ATT&CK Context:")
        for t in techs[:5]:
            lines.append(f"  • {t.get('id')} {t.get('name')}")

    mitigations = ctx.get("mitigations") or []
    if mitigations:
        lines.append("")
        lines.append("Mitigations:")
        for m in mitigations[:5]:
            lines.append(f"  • {m.get('id')} {m.get('name')}")

    phases = ctx.get("kill_chain_phases") or []
    if phases:
        lines.append("")
        lines.append(f"Kill chain phases: {', '.join(phases)}")

    lines.append("")
    lines.append("Related commands:")
    lines.append(f"  /rule {finding.ioc_value.upper()}" if finding.ioc_type == "cve_id"
                  else "  /ioc " + finding.ioc_value)
    lines.append(f"  /playbook {finding.id}           — Response playbook")
    lines.append(f"  /ack {finding.id}                — Acknowledge")
    lines.append(f"  /close {finding.id} --reason=X   — Close with reason")

    return "\n".join(lines)
