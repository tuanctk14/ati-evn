"""Format Finding -> Bot 1 Telegram message.

Vietnamese for narrative, English for technical terms.
"""
from __future__ import annotations

from ati_evn.config import get_settings
from ati_evn.db.models import Finding, Severity
from ati_evn.telegram.formatter.common import truncate

SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🚨",
    Severity.MEDIUM: "⚠️",
    Severity.LOW: "ℹ️",
}


def _analyst_bot_mention() -> str:
    username = get_settings().telegram_analyst_bot_username.strip()
    return f"@{username}" if username else "@<TELEGRAM_ANALYST_BOT_USERNAME>"


def format_alert_single(finding, customer_name, asset_display, attack_summary,
                          ingestion_source: str | None = None) -> str:
    """Format a single-finding alert message.

    Layout (target ~500 chars, plenty of room in Telegram's 4096 limit):

        🚨 EVN NPC — HIGH
        CVE-2024-12345 — Fortinet FortiOS Buffer Overflow
        Asset: fw-npc-01 (FortiGate 100F v7.2.4)
        Detected: 14/07/2026 15:30
        Finding #12847 · Sources: nvd, kev
        ATT&CK: T1190 (Initial Access)

        Xem chi tiết trong @evn_analyst_bot:
          /finding 12847
          /rule CVE-2024-12345
          /playbook 12847

    ingestion_source: when the finding originates from an analyst
    /ingest session (Detection.source == "analyst_ingested"), the
    article URL/filename to display with a 📥 badge (slice 7B).
    """
    emoji = SEVERITY_EMOJI.get(finding.severity, "•")
    sources = ", ".join(finding.sources or []) or "unknown"
    first_seen_local = finding.first_seen.strftime("%d/%m/%Y %H:%M")

    if finding.ioc_type == "cve_id":
        cve_line = f"{finding.ioc_value.upper()}"
    else:
        cve_line = f"{finding.ioc_type.upper()} {finding.ioc_value[:60]}"

    # Attack context summary — top 1 technique
    attack_line = ""
    ctx = (finding.metadata_ or {}).get("attack_context") or {}
    techs = ctx.get("techniques") or []
    if techs:
        top = techs[0]
        tactics = ctx.get("kill_chain_phases") or []
        tactic_str = f" ({tactics[0]})" if tactics else ""
        attack_line = f"\nATT&CK: {top['id']} — {top['name']}{tactic_str}"

    # Command hints
    cmd_lines = [f"  /finding {finding.id}"]
    if finding.ioc_type == "cve_id":
        cmd_lines.append(f"  /rule {finding.ioc_value.upper()}")
        cmd_lines.append(f"  /playbook {finding.id}")

    is_doc_leak = "exposed_document" in (finding.sources or [])
    is_brand_abuse = "brand_abuse" in (finding.sources or [])
    is_exposure = any(s.startswith("exposure_") for s in (finding.sources or []))
    is_ingested = "analyst_ingested" in (finding.sources or [])
    is_internal = "internal" in (finding.sources or [])

    prefix = ""
    tag = ""
    if is_doc_leak:
        prefix = "📄 "
        tag = " [DOC LEAK]"
    elif is_brand_abuse:
        prefix = "🎭 "
        tag = " [BRAND ABUSE]"
    elif is_exposure:
        prefix = "📡 "
        tag = " [EXPOSURE]"
    elif is_ingested:
        prefix = "📥 "
        tag = " [INGESTED]"
    elif is_internal:
        tag = " [INTERNAL]"

    exposure_line = ""
    if is_exposure:
        meta = finding.metadata_ or {}
        ip = meta.get("ip") or ""
        port = meta.get("port") or ""
        service = meta.get("service") or ""
        exposure_line = f"\nExposure: {ip}:{port} ({service})"

    doc_line = ""
    if is_doc_leak:
        meta = finding.metadata_ or {}
        bucket = meta.get("bucket_url") or ""
        filename = meta.get("filename") or ""
        keyword = meta.get("keyword_matched") or ""
        doc_line = (
            f"\nBucket: {bucket}"
            f"\nFile: {truncate(filename, 100)}"
            f"\nMatched keyword: {keyword}"
            f"\n⚠️ Truy cập file qua curl/tool riêng — không click trực tiếp"
        )

    brand_line = ""
    if is_brand_abuse:
        meta = finding.metadata_ or {}
        domain = meta.get("domain") or ""
        title = meta.get("page_title") or ""
        keyword = meta.get("keyword_matched") or ""
        typosquat_dist = meta.get("typosquat_distance")
        brand_line = (
            f"\nDomain: {domain}"
            f"\nPage title: {truncate(title, 100)}"
            f"\nMatched keyword: {keyword}"
        )
        if typosquat_dist is not None:
            brand_line += f"\nTyposquat distance: {typosquat_dist}"
        brand_line += "\n⚠️ Không truy cập trực tiếp URL — kiểm tra qua sandbox/tool riêng"

    ingest_line = f"\n📥 Ingested from: {truncate(ingestion_source, 100)}" if ingestion_source else ""

    return (
        f"{prefix}{emoji} {customer_name} — {finding.severity.value}{tag}\n"
        f"{cve_line} — {finding.title[:100]}\n"
        f"Asset: {asset_display}"
        f"{exposure_line}"
        f"{doc_line}"
        f"{brand_line}\n"
        f"Detected: {first_seen_local}\n"
        f"Finding #{finding.id} · Sources: {sources}"
        f"{attack_line}"
        f"{ingest_line}\n\n"
        f"Xem chi tiết trong {_analyst_bot_mention()}:\n"
        + "\n".join(cmd_lines)
    )


_TI_BADGE = {
    "brand_abuse": ("🎭", " [BRAND ABUSE]"),
    "exposed_document": ("📄", " [DOC LEAK]"),
    "exposure": ("📡", " [EXPOSURE]"),
    "ipv4": ("🔎", " [IOC]"),
    "ipv6": ("🔎", " [IOC]"),
    "domain": ("🔎", " [IOC]"),
    "url": ("🔎", " [IOC]"),
    "sha256": ("🔎", " [IOC]"),
    "sha1": ("🔎", " [IOC]"),
    "md5": ("🔎", " [IOC]"),
}


def format_indicator_alert(ti, customer_name: str) -> str:
    """Format a ThreatIndicator (slice 15A) -- non-CVE signal -- alert
    message. Analyst can only acknowledge/note these, never close/
    reopen/mark-FP the way a CVE Finding can.
    """
    prefix, tag = _TI_BADGE.get(ti.indicator_type, ("⚠️", " [INDICATOR]"))
    emoji = SEVERITY_EMOJI.get(ti.severity, "•")
    sources = ", ".join(ti.sources or []) or ti.source
    first_seen_local = ti.first_seen.strftime("%d/%m/%Y %H:%M")
    meta = ti.metadata_ or {}

    value_line = f"{ti.indicator_type.upper()} {ti.indicator_value[:60]}"

    detail_line = ""
    if ti.indicator_type == "exposure":
        ip = meta.get("ip") or ""
        port = meta.get("port") or ""
        service = meta.get("service") or ""
        detail_line = f"\nExposure: {ip}:{port} ({service})"
    elif ti.indicator_type == "exposed_document":
        bucket = meta.get("bucket_url") or ""
        filename = meta.get("filename") or ""
        keyword = meta.get("keyword_matched") or ""
        detail_line = (
            f"\nBucket: {bucket}"
            f"\nFile: {truncate(filename, 100)}"
            f"\nMatched keyword: {keyword}"
            f"\n⚠️ Truy cập file qua curl/tool riêng — không click trực tiếp"
        )
    elif ti.indicator_type == "brand_abuse":
        domain = meta.get("domain") or ""
        title = meta.get("page_title") or ""
        keyword = meta.get("keyword_matched") or ""
        typosquat_dist = meta.get("typosquat_distance")
        detail_line = (
            f"\nDomain: {domain}"
            f"\nPage title: {truncate(title, 100)}"
            f"\nMatched keyword: {keyword}"
        )
        if typosquat_dist is not None:
            detail_line += f"\nTyposquat distance: {typosquat_dist}"
        detail_line += "\n⚠️ Không truy cập trực tiếp URL — kiểm tra qua sandbox/tool riêng"

    return (
        f"{prefix} {emoji} {customer_name} — {ti.severity.value}{tag}\n"
        f"{value_line} — {ti.title[:100]}\n"
        f"Asset: {ti.matched_asset_value or '-'}"
        f"{detail_line}\n"
        f"Detected: {first_seen_local}\n"
        f"Indicator #{ti.id} · Sources: {sources}\n\n"
        f"ℹ️ Threat Indicator — chỉ theo dõi/note, không có close/reopen/FP như CVE finding.\n"
        f"Xem chi tiết trong {_analyst_bot_mention()}:\n"
        f"  /indicator {ti.id}\n"
        f"  /acknowledge_indicator {ti.id}"
    )


def format_alert_batch(batch, customer_name, findings_summary) -> str:
    """Format a batched digest message.

        📦 EVN NPC — Batch Alert (5 findings in 60s)
        • 1 CRITICAL: CVE-2024-99999 on fw-npc-01
        • 3 HIGH: CVE-2024-11111 (2 assets), CVE-2024-22222 (1 asset)
        • 1 MEDIUM+2src: 3.4.5.6 IOC on npc-net-cidr

        Đầy đủ danh sách trong @evn_analyst_bot:
          /list_alerts --recent=5m
    """
    sev_summary = " · ".join(
        f"{count} {sev}" for sev, count in
        sorted(batch.severities.items(),
               key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x[0], 9))
    )
    # findings_summary is caller-provided list of dicts:
    # [{severity, ioc_value, asset_display, finding_id}, ...]
    lines = []
    for f in findings_summary[:10]:  # cap at 10 to fit Telegram
        lines.append(f"• {f['severity']}: {f['ioc_value']} on {f['asset_display']}")
    if len(findings_summary) > 10:
        lines.append(f"...và {len(findings_summary) - 10} finding khác")

    return (
        f"📦 {customer_name} — Batch Alert "
        f"({batch.finding_count} findings in 60s)\n"
        f"{sev_summary}\n\n"
        + "\n".join(lines)
        + f"\n\nĐầy đủ danh sách trong {_analyst_bot_mention()}:\n"
          f"  /list_alerts --recent=5m"
    )
