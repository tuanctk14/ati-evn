"""Update severity/expiry/note for an internal-source IOC via agent.

Only source='internal' Detections are updatable (feed IOCs are
read-only, same restriction as /update_ioc).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from ati_evn.agent.tools._action_base import pending_confirmation, register_action_tool
from ati_evn.agent.tools._base import tool_error
from ati_evn.db.models import Detection, Finding, FindingStatus, Severity
from ati_evn.db.session import async_session

_SKIP_STATUSES = {FindingStatus.CLOSED, FindingStatus.FALSE_POSITIVE, FindingStatus.EXPIRED}


@register_action_tool(
    name="update_ioc",
    destructive=True,
    description=(
        "Update severity/expiry/note for an internal-source IOC (Detection). "
        "If severity changes, propagates the new severity to linked "
        "Findings that aren't already closed/FP/expired."
    ),
    parameters={
        "type": "object",
        "properties": {
            "detection_id": {"type": "integer"},
            "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
            "expire": {"type": "string", "description": "'30d' or 'clear'"},
            "note": {"type": "string"},
        },
        "required": ["detection_id"],
    },
)
async def update_ioc(
    detection_id: int, severity: str | None = None,
    expire: str | None = None, note: str | None = None,
    confirmed: bool = False,
) -> dict:
    async with async_session() as session:
        det = await session.get(Detection, detection_id)
        if not det:
            return tool_error(f"Detection #{detection_id} not found")
        if det.deleted_at:
            return tool_error(f"Detection #{detection_id} is soft-deleted. Restore first.")
        if det.source != "internal":
            return tool_error(f"Detection #{detection_id} has source='{det.source}' -- only internal IOCs are updatable.")
        current_severity = det.severity.value

    if not confirmed:
        return pending_confirmation({
            "action": "update_ioc",
            "detection_id": detection_id,
            "current_severity": current_severity,
            "new_severity": severity,
            "expire": expire,
            "note": note,
        })

    async with async_session() as session:
        det = await session.get(Detection, detection_id)
        if not det:
            return tool_error(f"Detection #{detection_id} not found")

        changes: dict[str, tuple] = {}
        severity_changed = False

        if severity:
            try:
                sev = Severity(severity.upper())
            except ValueError:
                return tool_error(f"severity không hợp lệ: {severity}")
            if sev != det.severity:
                changes["severity"] = (det.severity.value, sev.value)
                det.severity = sev
                severity_changed = True

        if expire is not None:
            if expire.lower() == "clear":
                if det.expires_at is not None:
                    changes["expires_at"] = (det.expires_at.isoformat(), None)
                    det.expires_at = None
            else:
                expire_str = expire.lower().strip()
                if expire_str.endswith("d") and expire_str[:-1].isdigit():
                    new_dt = datetime.now(timezone.utc) + timedelta(days=int(expire_str[:-1]))
                    changes["expires_at"] = (det.expires_at.isoformat() if det.expires_at else None, new_dt.isoformat())
                    det.expires_at = new_dt
                else:
                    return tool_error(f"--expire format không hợp lệ: {expire_str} (dùng '30d' hoặc 'clear')")

        if note and note != det.raw_text:
            changes["raw_text"] = (det.raw_text, note)
            det.raw_text = note

        if not changes:
            return {"status": "no_change", "detection_id": detection_id}

        findings_updated = 0
        if severity_changed:
            fnd_rows = await session.execute(
                select(Finding).where(Finding.ioc_type == det.ioc_type, Finding.ioc_value == det.ioc_value)
            )
            for f in fnd_rows.scalars():
                if f.status in _SKIP_STATUSES:
                    continue
                f.severity = det.severity
                findings_updated += 1

        await session.commit()

    return {
        "status": "updated",
        "detection_id": detection_id,
        "changes": {k: {"from": v[0], "to": v[1]} for k, v in changes.items()},
        "findings_updated": findings_updated,
    }
