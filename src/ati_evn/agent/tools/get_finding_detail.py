"""get_finding_detail — complete Finding record with ATT&CK context, matched
customer/asset (soft-delete aware), and related detections."""
from __future__ import annotations

from sqlalchemy import select

from ati_evn.agent.tools._base import register_tool, tool_error
from ati_evn.db.models import Customer, CustomerAsset, Detection, Finding
from ati_evn.db.session import async_session


@register_tool(
    name="get_finding_detail",
    description="Get full detail for a single Finding by ID, including ATT&CK context and related detections.",
    parameters={
        "type": "object",
        "properties": {
            "finding_id": {"type": "integer", "description": "Finding ID"},
        },
        "required": ["finding_id"],
    },
)
async def get_finding_detail(finding_id: int) -> dict:
    async with async_session() as session:
        finding = await session.get(Finding, finding_id)
        if not finding:
            return tool_error(
                f"Finding #{finding_id} not found",
                hint="Try /list_open or search_findings to find a valid finding_id.",
            )

        customer = await session.get(Customer, finding.customer_id)
        customer_dict = None
        if customer:
            customer_dict = {"id": customer.id, "name": customer.name}
            if customer.deleted_at:
                customer_dict["customer_status"] = "deleted"

        asset_dict = None
        if finding.matched_asset:
            asset_row = await session.execute(
                select(CustomerAsset).where(
                    CustomerAsset.customer_id == finding.customer_id,
                    CustomerAsset.asset_value == finding.matched_asset,
                ).limit(1)
            )
            asset = asset_row.scalar_one_or_none()
            if asset:
                asset_dict = {
                    "id": asset.id,
                    "asset_value": asset.asset_value,
                    "asset_type": asset.asset_type.value,
                    "vendor": asset.vendor,
                    "product": asset.product,
                    "version": asset.version,
                    "network_segment": asset.network_segment.value if asset.network_segment else None,
                }
                if asset.deleted_at:
                    asset_dict["asset_status"] = "deleted"

        det_rows = await session.execute(
            select(Detection.source, Detection.first_seen).where(
                Detection.finding_id == finding_id,
            )
        )
        related_detections = [
            {"source": s, "first_seen": fs.isoformat()} for s, fs in det_rows.all()
        ]

        attack_context = (finding.metadata_ or {}).get("attack_context") or {}

        return {
            "id": finding.id,
            "ioc_type": finding.ioc_type,
            "ioc_value": finding.ioc_value,
            "title": finding.title,
            "cve_id": finding.cve_id,
            "severity": finding.severity.value,
            "status": finding.status.value,
            "confidence": finding.confidence,
            "matched_asset": finding.matched_asset,
            "correlation_type": finding.correlation_type,
            "detection_reason": finding.detection_reason,
            "source_count": finding.source_count,
            "sources": finding.sources or [],
            "first_seen": finding.first_seen.isoformat(),
            "last_seen": finding.last_seen.isoformat(),
            "closed_at": finding.closed_at.isoformat() if finding.closed_at else None,
            "closed_by": finding.closed_by,
            "closed_reason": finding.closed_reason,
            "customer": customer_dict,
            "asset": asset_dict,
            "attack_context": attack_context,
            "related_detections": related_detections,
        }
