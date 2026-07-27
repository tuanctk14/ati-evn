"""Manually add an IOC (Detection, source='internal') via agent.

Reuses the same logic as /add_ioc: creates a Detection then runs an
immediate matcher pass (customer_router) so matched assets can spawn
Findings -> alert_queue -> Bot 1 dispatch.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ati_evn.agent.tools._action_base import pending_confirmation, register_action_tool
from ati_evn.agent.tools._base import tool_error
from ati_evn.db.models import Detection, DetectionStatus, Severity
from ati_evn.db.session import async_session
from ati_evn.match.customer_router import route_detections

VALID_IOC_TYPES = {"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email", "cve_id"}


@register_action_tool(
    name="add_ioc",
    destructive=True,
    description=(
        "Manually add an IOC (source='internal'). Runs an immediate matcher "
        "pass against customer assets -- matches can create Findings and "
        "trigger a Bot 1 alert if severity qualifies."
    ),
    parameters={
        "type": "object",
        "properties": {
            "ioc_type": {"type": "string", "enum": sorted(VALID_IOC_TYPES)},
            "value": {"type": "string"},
            "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"], "default": "MEDIUM"},
            "note": {"type": "string"},
            "expire_days": {"type": "integer", "description": "TTL in days, optional"},
            "malware": {"type": "string", "description": "Malware family name, optional"},
        },
        "required": ["ioc_type", "value"],
    },
)
async def add_ioc(
    ioc_type: str, value: str, severity: str = "MEDIUM",
    note: str = "", expire_days: int | None = None, malware: str = "",
    confirmed: bool = False,
) -> dict:
    ioc_type = ioc_type.lower()
    if ioc_type not in VALID_IOC_TYPES:
        return tool_error(f"ioc_type không hợp lệ: {ioc_type}. Valid: {sorted(VALID_IOC_TYPES)}")

    try:
        sev = Severity(severity.upper())
    except ValueError:
        return tool_error(f"severity không hợp lệ: {severity}")

    if not confirmed:
        return pending_confirmation({
            "action": "add_ioc",
            "ioc_type": ioc_type,
            "value": value,
            "severity": sev.value,
            "expire_days": expire_days,
            "malware": malware or None,
        })

    expires_at = None
    if expire_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=expire_days)

    det_metadata = {"added_by": "agent"}
    if malware:
        det_metadata["malware_printable"] = malware

    async with async_session() as session:
        det = Detection(
            source="internal",
            ioc_type=ioc_type,
            ioc_value=value.lower().strip(),
            raw_text=note or "Manual IOC added via agent",
            severity=sev,
            status=DetectionStatus.NEW,
            expires_at=expires_at,
            metadata_=det_metadata,
        )
        session.add(det)
        await session.commit()
        detection_id = det.id

    try:
        async with async_session() as session:
            stats = await route_detections(session, only_new=True)
    except Exception as e:
        return {
            "status": "created_matcher_failed",
            "detection_id": detection_id,
            "error": str(e)[:200],
        }

    return {
        "status": "created",
        "detection_id": detection_id,
        "ioc_type": ioc_type,
        "value": value,
        "severity": sev.value,
        "matcher_matched": stats.detections_matched,
        "findings_created": stats.findings_created,
    }
