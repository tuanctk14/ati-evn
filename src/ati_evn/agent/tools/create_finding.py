"""Manually create a Finding via agent.

Schema note: Finding has no `updated_at` column (only first_seen/last_seen/
closed_at), so no timestamp is touched beyond the ones the model defines.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select

from ati_evn.agent.tools._action_base import pending_confirmation, register_action_tool
from ati_evn.agent.tools._base import tool_error
from ati_evn.alerts.dispatch_rule import should_dispatch
from ati_evn.db.models import AlertQueue, Customer, Finding, FindingStatus, Severity
from ati_evn.db.query_utils import customer_name_or_code_match
from ati_evn.db.session import async_session


@register_action_tool(
    name="create_finding",
    destructive=True,
    description=(
        "Manually create a Finding for a customer. Use when analyst found "
        "a threat outside the automated detection pipeline. Also enqueues "
        "an AlertQueue entry if severity meets the dispatch rule "
        "(HIGH/CRITICAL, or MEDIUM with source_count>=2 -- a fresh manual "
        "finding always has source_count=1, so only HIGH/CRITICAL alert)."
    ),
    parameters={
        "type": "object",
        "properties": {
            "customer": {"type": "string", "description": "Customer name or short_code"},
            "title": {"type": "string"},
            "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
            "ioc_type": {"type": "string", "description": "cve_id, ipv4, ipv6, domain, url, sha256, etc."},
            "ioc_value": {"type": "string"},
            "description": {"type": "string"},
            "matched_asset": {"type": "string", "description": "Which asset triggered this"},
        },
        "required": ["customer", "title", "severity", "ioc_type", "ioc_value"],
    },
)
async def create_finding(
    customer: str, title: str, severity: str,
    ioc_type: str, ioc_value: str,
    description: str = "", matched_asset: str = "",
    confirmed: bool = False,
) -> dict:
    async with async_session() as session:
        row = await session.execute(
            select(Customer.id, Customer.name).where(
                customer_name_or_code_match(customer),
                Customer.deleted_at.is_(None),
            ).limit(1)
        )
        r = row.first()
        if not r:
            return tool_error(f"Customer '{customer}' not found")
        customer_id = r.id
        customer_name = r.name

    if not confirmed:
        return pending_confirmation({
            "action": "create_finding",
            "customer": customer_name,
            "title": title,
            "severity": severity,
            "ioc": f"{ioc_type}:{ioc_value[:60]}",
            "will_alert": severity in ("CRITICAL", "HIGH"),
        })

    try:
        sev_enum = Severity(severity)
    except ValueError:
        return tool_error(f"Invalid severity: {severity}")

    now = datetime.now(timezone.utc)
    async with async_session() as session:
        finding = Finding(
            customer_id=customer_id,
            ioc_type=ioc_type,
            ioc_value=ioc_value[:500],
            title=title[:500],
            severity=sev_enum,
            status=FindingStatus.OPEN,
            matched_asset=matched_asset[:200] if matched_asset else None,
            detection_reason=f"Manual creation by analyst: {description[:400]}",
            sources=["manual"],
            source_count=1,
            first_seen=now,
            last_seen=now,
            metadata_={"manual_creation": True, "created_via": "agent_tool"},
        )
        session.add(finding)
        await session.flush()

        alerted = False
        ok, reason = should_dispatch(finding)
        if ok:
            from ati_evn.alerts.dedupe import compute_dedupe_key, find_existing_dispatch
            from ati_evn.config import get_settings

            settings = get_settings()
            dedupe_key = compute_dedupe_key(finding.customer_id, finding.ioc_value, None)
            existing_id = await find_existing_dispatch(session, dedupe_key, settings.alert_dedupe_window_minutes)
            state = "deduped" if existing_id else "pending"
            queue = AlertQueue(
                finding_id=finding.id,
                customer_id=finding.customer_id,
                state=state,
                dispatch_reason=reason,
                dedupe_key=dedupe_key,
                deduped_of_id=existing_id,
            )
            session.add(queue)
            alerted = True

        await session.commit()
        await session.refresh(finding)
        finding_id = finding.id

    return {
        "status": "created",
        "finding_id": finding_id,
        "customer": customer_name,
        "severity": severity,
        "will_alert": alerted,
    }
