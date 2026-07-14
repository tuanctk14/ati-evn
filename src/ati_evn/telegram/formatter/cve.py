"""Format CVE detail -> Bot 2 /cve response."""
from __future__ import annotations

from ati_evn.telegram.formatter.common import truncate


def format_cve_detail(cve_id, description, cvss, cwe_ids, attack_ctx, product_map) -> str:
    lines = [
        f"🛡️ {cve_id}",
        "",
        f"Description: {truncate(description, 500)}",
        f"CVSS: {cvss if cvss is not None else 'unknown'}",
        f"CWE: {', '.join(cwe_ids) if cwe_ids else '-'}",
    ]

    if product_map:
        lines.append("")
        lines.append("Product mapping:")
        for p in product_map[:8]:
            vendor = p.vendor or "?"
            product = p.product
            vr = f" {p.version_range}" if p.version_range else ""
            lines.append(f"  • {vendor}/{product}{vr} (source={p.source})")

    attack_ctx = attack_ctx or {}
    techs = attack_ctx.get("techniques") or []
    if techs:
        lines.append("")
        lines.append("ATT&CK Context:")
        for t in techs[:5]:
            lines.append(f"  • {t.get('id')} {t.get('name')}")

    mitigations = attack_ctx.get("mitigations") or []
    if mitigations:
        lines.append("")
        lines.append("Mitigations:")
        for m in mitigations[:5]:
            lines.append(f"  • {m.get('id')} {m.get('name')}")

    phases = attack_ctx.get("kill_chain_phases") or []
    if phases:
        lines.append("")
        lines.append(f"Kill chain phases: {', '.join(phases)}")

    lines.append("")
    lines.append("Related commands:")
    lines.append(f"  /rule {cve_id}       — Sigma rule")

    return "\n".join(lines)
