"""search_malicious_ips -- IPs by aggregated multi-provider risk score."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from ati_evn.agent.tools._base import register_tool
from ati_evn.db.models import Finding, IpAggregatedScore
from ati_evn.db.session import async_session


@register_tool(
    name="search_malicious_ips",
    description=(
        "Search IPs by aggregated multi-provider risk score. Filter by "
        "min score, min confidence, min coverage, since_days. Returns "
        "IPs ordered by aggregate_risk_score DESC."
    ),
    parameters={
        "type": "object",
        "properties": {
            "min_aggregate_score": {"type": "number", "default": 50},
            "min_confidence": {"type": "number", "default": 0, "description": "0-1"},
            "min_coverage": {"type": "number", "default": 0, "description": "0-1"},
            "since_days": {"type": "integer", "description": "Aggregate calculated within N days"},
            "limit": {"type": "integer", "default": 20},
        },
        "required": [],
    },
)
async def search_malicious_ips(
    min_aggregate_score: float = 50,
    min_confidence: float = 0,
    min_coverage: float = 0,
    since_days: int | None = None,
    limit: int = 20,
) -> dict:
    limit = min(max(limit, 1), 50)
    async with async_session() as session:
        stmt = select(IpAggregatedScore).where(
            IpAggregatedScore.aggregate_risk_score >= min_aggregate_score,
            IpAggregatedScore.confidence_score >= min_confidence,
            IpAggregatedScore.coverage_score >= min_coverage,
        )
        count_stmt = select(func.count(IpAggregatedScore.ip)).where(
            IpAggregatedScore.aggregate_risk_score >= min_aggregate_score,
            IpAggregatedScore.confidence_score >= min_confidence,
            IpAggregatedScore.coverage_score >= min_coverage,
        )
        if since_days:
            cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)
            stmt = stmt.where(IpAggregatedScore.last_calculated_at >= cutoff)
            count_stmt = count_stmt.where(IpAggregatedScore.last_calculated_at >= cutoff)

        total = (await session.execute(count_stmt)).scalar() or 0
        stmt = stmt.order_by(IpAggregatedScore.aggregate_risk_score.desc()).limit(limit)
        rows = list((await session.execute(stmt)).scalars())

        result = []
        for r in rows:
            f_count = (await session.execute(
                select(func.count(Finding.id)).where(Finding.ioc_value == r.ip)
            )).scalar() or 0
            result.append({
                "ip": r.ip,
                "aggregate_risk_score": r.aggregate_risk_score,
                "max_provider_score": r.max_provider_score,
                "confidence_score": r.confidence_score,
                "coverage_score": r.coverage_score,
                "positive_provider_count": r.positive_provider_count,
                "supporting_provider_count": r.supporting_provider_count,
                "provider_mask": r.provider_mask,
                "provider_verdicts": r.provider_verdicts or {},
                "consensus_status": r.consensus_status,
                "linked_findings_count": f_count,
                "last_calculated_at": r.last_calculated_at.isoformat() if r.last_calculated_at else None,
            })

    return {
        "total_count": total,
        "returned_count": len(result),
        "malicious_ips": result,
    }
