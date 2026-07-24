"""get_ip_enrichment -- multi-provider enrichment + aggregate for one IP."""
from __future__ import annotations

from sqlalchemy import select

from ati_evn.agent.tools._base import register_tool
from ati_evn.db.models import IpAggregatedScore, IpEnrichment
from ati_evn.db.session import async_session


@register_tool(
    name="get_ip_enrichment",
    description=(
        "Get multi-provider enrichment for an IP: per-provider verdicts "
        "(AbuseIPDB, VirusTotal, OTX, Pulsedive, LeakIX) + aggregated "
        "risk_score with confidence and coverage metadata."
    ),
    parameters={
        "type": "object",
        "properties": {
            "ip": {"type": "string"},
            "provider": {"type": "string", "description": "Optional: single provider name"},
        },
        "required": ["ip"],
    },
)
async def get_ip_enrichment(ip: str, provider: str | None = None) -> dict:
    async with async_session() as session:
        e_stmt = select(IpEnrichment).where(IpEnrichment.ip == ip)
        if provider:
            e_stmt = e_stmt.where(IpEnrichment.provider == provider)
        enrichments = list((await session.execute(e_stmt)).scalars())

        agg = None
        if not provider:
            agg = await session.get(IpAggregatedScore, ip)

    if not enrichments and not agg:
        return {
            "ip": ip,
            "enrichments": [],
            "aggregate": None,
            "note": "No enrichment data yet — background scheduler will pick up within 15 min.",
        }

    return {
        "ip": ip,
        "enrichments": [
            {
                "provider": r.provider,
                "verdict": r.verdict,
                "verdict_confidence": r.verdict_confidence,
                "risk_score": r.risk_score,
                "country": r.country,
                "isp": r.isp,
                "data": r.data or {},
                "queried_at": r.queried_at.isoformat() if r.queried_at else None,
                "error": r.error_message,
            }
            for r in enrichments
        ],
        "aggregate": (
            {
                "aggregate_risk_score": agg.aggregate_risk_score,
                "max_provider_score": agg.max_provider_score,
                "confidence_score": agg.confidence_score,
                "coverage_score": agg.coverage_score,
                "positive_provider_count": agg.positive_provider_count,
                "supporting_provider_count": agg.supporting_provider_count,
                "responded_provider_count": agg.responded_provider_count,
                "enabled_provider_count": agg.enabled_provider_count,
                "provider_mask": agg.provider_mask,
                "provider_verdicts": agg.provider_verdicts or {},
                "consensus_status": agg.consensus_status,
                "last_calculated_at": agg.last_calculated_at.isoformat() if agg.last_calculated_at else None,
            }
            if agg else None
        ),
    }
