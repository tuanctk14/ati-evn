"""Trigger IP enrichment via agent -- non-destructive (only queries APIs).

Note: get_ip_enrichment (existing read-only tool) reads cached
IpEnrichment rows only. This tool actually calls the providers.
"""
from __future__ import annotations

from ati_evn.agent.tools._action_base import register_action_tool
from ati_evn.agent.tools._base import tool_error
from ati_evn.enrichment_v2.ip_enricher import enrich_ip_foreground, enrich_ip_full


@register_action_tool(
    name="enrich_ip",
    destructive=False,
    description=(
        "Enrich an IP via multi-source providers (live API calls). "
        "Default: foreground (AbuseIPDB + VirusTotal, ~5s). "
        "full=true: all 5 providers (~15-30s)."
    ),
    parameters={
        "type": "object",
        "properties": {
            "ip": {"type": "string"},
            "full": {"type": "boolean", "default": False, "description": "Query all 5 providers"},
            "force": {"type": "boolean", "default": False, "description": "Bypass cache TTL"},
        },
        "required": ["ip"],
    },
)
async def action_enrich_ip(ip: str, full: bool = False, force: bool = False) -> dict:
    try:
        if full:
            results, agg = await enrich_ip_full(ip, force=force)
        else:
            results, agg = await enrich_ip_foreground(ip, force=force)
    except Exception as e:
        return tool_error(f"Enrichment failed: {str(e)[:200]}")

    return {
        "ip": ip,
        "providers_queried": len(results),
        "per_provider": results,
        "aggregate": (
            {
                "risk_score": agg.aggregate_risk_score,
                "confidence": agg.confidence_score,
                "coverage": agg.coverage_score,
                "positive_count": agg.positive_provider_count,
                "consensus_status": agg.consensus_status,
            }
            if agg else None
        ),
    }
