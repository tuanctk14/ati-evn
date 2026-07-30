"""Campaign detail + list formatter."""
from ati_evn.campaigns.notify import _sort_tactics
from ati_evn.telegram.formatter.common import fmt_dt, fmt_severity, truncate


def format_campaign_detail(campaign, customer, findings) -> str:
    span = (campaign.window_end - campaign.window_start).total_seconds() / 3600
    tactics_sorted = _sort_tactics(campaign.tactic_ids or [])

    status_emoji = {
        "candidate": "🎯",
        "confirmed": "🔴",
        "rejected": "⚪",
        "expired": "⏱",
    }.get(campaign.status, "•")

    lines = [
        f"{status_emoji} Campaign #{campaign.id} — {campaign.status.upper()}",
        f"Customer: {customer.name if customer else '?'}",
        f"Window: {fmt_dt(campaign.window_start)} → {fmt_dt(campaign.window_end)}",
        f"Duration: {span:.1f}h",
        f"Confidence: {campaign.confidence:.2f}",
        "",
        f"Findings: {campaign.finding_count} · "
        f"Assets: {campaign.asset_count} · "
        f"Sources: {', '.join(campaign.source_ids or []) or '-'}",
    ]

    sev_line = " · ".join(
        f"{v} {k}" for k, v in
        sorted((campaign.severities or {}).items(),
               key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x[0], 9))
    )
    if sev_line:
        lines.append(f"Severity: {sev_line}")

    if tactics_sorted:
        lines.append(f"\nKill chain: {' → '.join(tactics_sorted)}")

    from ati_evn.enrichment.attack_catalog import get_technique_name
    if campaign.technique_ids:
        lines.append(f"\nTechniques ({len(campaign.technique_ids)}):")
        for tid in campaign.technique_ids[:12]:
            name = get_technique_name(tid)
            lines.append(f"  • {tid} — {name}")
        if len(campaign.technique_ids) > 12:
            lines.append(f"  … và {len(campaign.technique_ids) - 12} technique khác")

    if campaign.detection_reason:
        lines.append(f"\nDetection reason:\n  {campaign.detection_reason}")

    if campaign.reviewed_by:
        lines.append(
            f"\nReviewed: {campaign.reviewed_at and fmt_dt(campaign.reviewed_at) or '-'} "
            f"by @{campaign.reviewed_by}"
        )
        if campaign.review_notes:
            lines.append(f"Notes: {truncate(campaign.review_notes, 300)}")

    if findings:
        lines.append(f"\nLinked findings ({len(findings)}):")
        for f in findings[:10]:
            lines.append(
                f"  #{f.id} — {fmt_severity(f.severity.value)} · "
                f"{truncate(f.ioc_value, 40)} · {f.matched_asset or '-'}"
            )
        if len(findings) > 10:
            lines.append(f"  … và {len(findings) - 10} finding khác")

    lines.append("")
    if campaign.status == "candidate":
        lines.append("Actions:")
        lines.append(f"  /confirm_campaign {campaign.id} --notes=X")
        lines.append(f"  /reject_campaign {campaign.id} --reason=X")

    return "\n".join(lines)


def format_campaign_list(campaigns, customer_names, total, page, per_page,
                          status_filter) -> str:
    if not campaigns:
        return f"Không có campaign với status={status_filter}."
    pages = max(1, (total + per_page - 1) // per_page)
    lines = [f"📋 Campaign list — status={status_filter}"]
    for c in campaigns:
        cust = customer_names.get(c.customer_id, f"#{c.customer_id}")
        span = (c.window_end - c.window_start).total_seconds() / 3600
        lines.append(
            f"  #{c.id} · {cust} · conf {c.confidence:.2f} · "
            f"{c.finding_count} findings / {span:.1f}h · "
            f"{','.join((c.technique_ids or [])[:3])}"
        )
    lines.append(f"\nTrang {page}/{pages} (tổng {total}).")
    return "\n".join(lines)
