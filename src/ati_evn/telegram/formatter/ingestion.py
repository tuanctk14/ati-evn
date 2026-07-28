"""Format ingestion extraction preview."""
from __future__ import annotations

from ati_evn.telegram.formatter.common import truncate


def format_preview(
    session_id: int,
    source_type: str,
    source_url: str | None,
    source_filename: str | None,
    data: dict,
) -> str:
    lines = [f"📥 Ingestion Preview #{session_id}"]

    if source_type == "url":
        lines.append(f"Source: {source_url}")
    elif source_type == "pdf":
        lines.append(f"Source: PDF — {source_filename or 'attached'}")
    else:
        lines.append(f"Source: text ({source_type})")

    conf = data.get("confidence", 0)
    lines.append(f"Extraction confidence: {conf:.2f}")

    summary = data.get("summary") or ""
    if summary:
        lines.append(f"\n📝 {truncate(summary, 500)}")

    iocs = data.get("iocs") or []
    if iocs:
        lines.append(f"\n🎯 IOCs ({len(iocs)}):")
        for i, ioc in enumerate(iocs[:20], 1):
            ctx = f" — {truncate(ioc.get('context') or '', 60)}" if ioc.get("context") else ""
            lines.append(f"  [{i}] {ioc['type']}: {ioc['value']}{ctx}")
        if len(iocs) > 20:
            lines.append(f"  … và {len(iocs) - 20} IOC nữa")

    cves = data.get("cves") or []
    if cves:
        lines.append(f"\n🔓 CVEs ({len(cves)}):")
        for i, cve in enumerate(cves[:15], 1):
            ctx = f" — {truncate(cve.get('context') or '', 80)}" if cve.get("context") else ""
            lines.append(f"  [{i}] {cve['id']}{ctx}")
        if len(cves) > 15:
            lines.append(f"  … và {len(cves) - 15} CVE nữa")

    malware = data.get("malware_families") or []
    if malware:
        lines.append(f"\n🦠 Malware: {', '.join(malware[:10])}")

    techs = data.get("attack_techniques") or []
    if techs:
        lines.append(f"⚔️ ATT&CK: {', '.join(techs[:15])}")

    sectors = data.get("sectors_targeted") or []
    if sectors:
        lines.append(f"🎯 Sectors: {', '.join(sectors[:10])}")

    attribution = data.get("attribution_hints") or ""
    if attribution and attribution != "Not attributed":
        lines.append(f"👥 Attribution: {truncate(attribution, 200)}")

    lines.append(
        f"\nActions:\n"
        f"  ✅ /confirm_ingest {session_id}\n"
        f"  ❌ /reject_ingest {session_id} --reason=X\n"
        f"  ✏️ /edit_ingest {session_id} --drop=1,3,5 --drop-cves=2"
    )

    return "\n".join(lines)
