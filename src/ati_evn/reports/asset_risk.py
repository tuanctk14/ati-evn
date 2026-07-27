"""Aggregate finding counts + risk score per customer asset.

Formula:
  severity_score = CRITICAL*100 + HIGH*40 + MEDIUM*15 + LOW*5
  + max IP aggregated risk score if asset is IP with enrichment
"""
from __future__ import annotations

import logging
from datetime import datetime

from sqlalchemy import select

from ati_evn.db.models import CustomerAsset, Customer, Finding, IpAggregatedScore
from ati_evn.db.query_utils_test import is_test_finding
from ati_evn.db.session import async_session

logger = logging.getLogger("ati_evn.reports.asset_risk")

SEVERITY_WEIGHTS = {"CRITICAL": 100, "HIGH": 40, "MEDIUM": 15, "LOW": 5}


async def compute_asset_risk_ranking(
    from_dt: datetime, to_dt: datetime,
    customer_id: int | None = None, limit: int = 20,
) -> list[dict]:
    """Aggregate per-asset finding counts + risk score.

    Returns list of {asset_value, asset_type, customer, ...} sorted
    by risk_score desc.
    """
    async with async_session() as session:
        stmt = select(Finding).where(
            Finding.first_seen >= from_dt,
            Finding.first_seen < to_dt,
        )
        if customer_id:
            stmt = stmt.where(Finding.customer_id == customer_id)
        all_findings = list((await session.execute(stmt)).scalars())
        all_findings = [f for f in all_findings if not is_test_finding(f)]

        asset_groups: dict[str, dict] = {}
        for f in all_findings:
            key = (f.matched_asset or f.ioc_value or "").strip()
            if not key:
                continue
            if key not in asset_groups:
                asset_groups[key] = {
                    "asset_value": key[:120],
                    "customer_id": f.customer_id,
                    "ioc_types": set(),
                    "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                    "finding_ids": [],
                }
            grp = asset_groups[key]
            grp["ioc_types"].add(f.ioc_type)
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            grp["counts"][sev] = grp["counts"].get(sev, 0) + 1
            grp["finding_ids"].append(f.id)

        customer_names: dict[int, str | None] = {}
        for grp in asset_groups.values():
            cid = grp["customer_id"]
            if cid and cid not in customer_names:
                c = await session.get(Customer, cid)
                customer_names[cid] = c.name if c else None

        ip_aggregates: dict[str, float] = {}
        ip_keys = [
            k for k, g in asset_groups.items()
            if any(t in ("ipv4", "ipv6") for t in g["ioc_types"])
        ]
        if ip_keys:
            agg_stmt = select(IpAggregatedScore).where(IpAggregatedScore.ip.in_(ip_keys))
            for row in (await session.execute(agg_stmt)).scalars():
                ip_aggregates[row.ip] = row.aggregate_risk_score or 0

        asset_type_map: dict[str, str] = {}
        asset_values = list(asset_groups.keys())
        if asset_values:
            asset_stmt = select(
                CustomerAsset.asset_value, CustomerAsset.asset_type,
            ).where(
                CustomerAsset.asset_value.in_(asset_values),
                CustomerAsset.deleted_at.is_(None),
            )
            for row in await session.execute(asset_stmt):
                at = row.asset_type
                asset_type_map[row.asset_value] = at.value if hasattr(at, "value") else str(at)

    result = []
    for key, grp in asset_groups.items():
        counts = grp["counts"]
        severity_score = sum(counts.get(sev, 0) * w for sev, w in SEVERITY_WEIGHTS.items())
        ip_score = int(ip_aggregates.get(key, 0))
        total_score = severity_score + ip_score

        result.append({
            "asset_value": grp["asset_value"],
            "asset_type": asset_type_map.get(key, "unknown"),
            "customer": customer_names.get(grp["customer_id"]) or "(orphan)",
            "ioc_types": sorted(grp["ioc_types"]),
            "critical": counts.get("CRITICAL", 0),
            "high": counts.get("HIGH", 0),
            "medium": counts.get("MEDIUM", 0),
            "low": counts.get("LOW", 0),
            "finding_count": sum(counts.values()),
            "severity_score": severity_score,
            "ip_aggregate_score": ip_score if ip_score else None,
            "risk_score": total_score,
            "finding_ids": grp["finding_ids"][:5],
        })

    result.sort(key=lambda x: x["risk_score"], reverse=True)
    return result[:limit]
